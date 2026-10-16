/**
 * The custom report agent. For one CustomReport it:
 *   1. checks the org's AI provider accepts requests (fails clearly if not),
 *   2. loads the scan's data and fills the template's {{placeholders}},
 *   3. plans: one call decides which data tools each template section needs,
 *   4. writes each section (bounded concurrency) from those tool results — the
 *      model may ask for more data, up to MAX_SECTION_ROUNDS rounds,
 *   5. assembles the sections in template order and runs the grounding check
 *      (cited findings must exist; invalid citations are removed), then adds a
 *      data-built appendix of referenced findings,
 *   6. masks secrets, renders sanitized HTML and stores the result.
 *
 * Progress (stage, percentage, step log) is written to the row as it goes so
 * the UI can poll it. Runs in the worker (see src/worker/index.ts).
 */
import { prisma } from "@/lib/prisma";
import { Prisma } from "@/generated/prisma/client";
import {
  analyzeWithLlm,
  createLlmClient,
  getLlmConfig,
  parseLlmJsonResponseDetailed,
} from "@/lib/llm-gateway";
import { checkLlmAvailable } from "@/lib/llm-preflight";
import { createRedactionSession } from "@/lib/llm-redaction";
import { writeAuditLog } from "@/lib/audit-log";
import { logger } from "@/lib/logger";
import { MAX_CALLS_PER_ROUND, PLAN_SYSTEM, WRITE_SYSTEM } from "./prompts";
import {
  fillPlaceholders,
  normalizeTemplateBody,
  templateSections,
  type TemplateSection,
} from "./template";
import {
  placeholderValues,
  runTool,
  toolCallKey,
  TOOL_NAMES,
  type ReportData,
  type ReportSources,
  type ToolCall,
} from "./tools";
import { groundReport, referencedFindingsAppendix } from "./grounding";
import { buildCustomReportHtml } from "./render";
import { stripRawHtml } from "./markdown";
import { createReportSources, loadReportData } from "./sources";

/** Write rounds per section: the first answer plus up to two data requests. */
export const MAX_SECTION_ROUNDS = 3;
const SECTION_CONCURRENCY = Math.max(1, parseInt(process.env.REPORT_LLM_CONCURRENCY || "3") || 3);
/** Characters of tool results sent with one section (≈10k tokens). */
const DATA_BUDGET_CHARS = 40_000;
const PLAN_MAX_TOKENS = 3_000;
const WRITE_MAX_TOKENS = 6_000;
const GUIDANCE_CHARS = 4_000;
const MAX_STEPS_LOGGED = 80;

export interface TemplateSnapshot {
  name: string;
  format: string;
  body: string;
  instructions: string | null;
}

export interface ReportStep {
  at: string;
  message: string;
}

/** The LLM as the agent uses it: system + user in, raw (JSON) text out. */
export type LlmCall = (system: string, user: string, maxTokens: number) => Promise<string>;

class ReportFailure extends Error {}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Validate tool calls the model proposed: known tools only, bounded count. */
export function sanitizeToolCalls(raw: unknown, max = MAX_CALLS_PER_ROUND): ToolCall[] {
  if (!Array.isArray(raw)) return [];
  const out: ToolCall[] = [];
  for (const c of raw) {
    if (!c || typeof c !== "object") continue;
    const tool = (c as { tool?: unknown }).tool;
    const args = (c as { args?: unknown }).args;
    if (typeof tool !== "string" || !TOOL_NAMES.has(tool)) continue;
    out.push({ tool, args: args && typeof args === "object" && !Array.isArray(args) ? (args as Record<string, unknown>) : {} });
    if (out.length >= max) break;
  }
  return out;
}

/** Tool results as prompt text, trimmed to the section's data budget. */
export function formatToolResults(
  results: Array<{ call: ToolCall; result: unknown }>,
  mask: (json: string) => string = (s) => s,
  budget = DATA_BUDGET_CHARS,
): string {
  const parts: string[] = [];
  let used = 0;
  for (const { call, result } of results) {
    // Masked as JSON so secrets inside escaped code strings are caught too.
    let text = mask(JSON.stringify(result));
    const head = `### ${call.tool} ${JSON.stringify(call.args ?? {})}\n`;
    const room = budget - used - head.length;
    if (room <= 200) {
      parts.push(`### ${call.tool}: omitted (data budget reached)`);
      continue;
    }
    if (text.length > room) text = `${text.slice(0, room)}… [truncated — ask for a narrower filter]`;
    parts.push(head + text);
    used += head.length + text.length;
  }
  return parts.join("\n\n");
}

/** Remove a leading heading that just repeats the section heading. */
function stripRepeatedHeading(md: string, heading: string): string {
  const m = md.match(/^\s*#{1,6}\s+(.+?)\s*#*\s*\n/);
  if (m && heading && m[1].trim().toLowerCase() === heading.trim().toLowerCase()) return md.slice(m[0].length);
  return md;
}

async function mapPool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

export interface GenerateInput {
  data: ReportData;
  sources: ReportSources;
  template: TemplateSnapshot;
  extraInstructions: string | null;
  llm: LlmCall;
  /** Secret masking for tool results (JSON text in, masked JSON out). */
  maskData?: (json: string) => string;
  now: Date;
  onProgress?: (progress: number, stage: string, step?: string) => Promise<void> | void;
}

export interface GenerateOutput {
  title: string;
  markdown: string;
  grounding: ReturnType<typeof groundReport> & { emptySections: number };
  llmCalls: number;
}

/**
 * The pipeline itself, free of the job row: plan → fetch → write → assemble →
 * ground. Throws ReportFailure when the model produced nothing usable.
 */
export async function generateCustomReport(input: GenerateInput): Promise<GenerateOutput> {
  const { data, sources, template, llm, now } = input;
  const progress = async (p: number, stage: string, step?: string) => input.onProgress?.(p, stage, step);
  let llmCalls = 0;
  const call: LlmCall = async (system, user, maxTokens) => {
    llmCalls++;
    return llm(system, user, maxTokens);
  };

  // Placeholders are filled before any AI step so their values are exact.
  const delta = await sources.delta();
  const filled = fillPlaceholders(
    normalizeTemplateBody(template.format, template.body),
    placeholderValues(data, delta, now),
  );
  const { title: templateTitle, sections } = templateSections(filled);
  const title = templateTitle || template.name;
  const instructions = [template.instructions, input.extraInstructions].filter((s) => s && s.trim()).join("\n\n");

  // Tool results are shared across sections: the same call runs once.
  const cache = new Map<string, Promise<unknown>>();
  const exec = (c: ToolCall) => {
    const key = toolCallKey(c);
    if (!cache.has(key)) cache.set(key, runTool(data, sources, c));
    return cache.get(key)!;
  };

  // ── Plan ──
  await progress(10, "Planning the report", `Template has ${sections.length} section(s)`);
  const overview = await exec({ tool: "get_scan_summary", args: {} });
  const planRaw = await call(
    PLAN_SYSTEM,
    JSON.stringify({
      reportTitle: title,
      instructions: instructions || undefined,
      scanOverview: overview,
      sections: sections.map((s) => ({ index: s.index, heading: s.heading || "(introduction)", template: s.body.slice(0, 600) })),
    }),
    PLAN_MAX_TOKENS,
  );
  const plan = parseLlmJsonResponseDetailed<{ sections?: Array<{ index?: number; toolCalls?: unknown }> }>(planRaw, {});
  const planned = new Map<number, ToolCall[]>();
  for (const s of plan.value.sections ?? []) {
    if (typeof s?.index === "number") planned.set(s.index, sanitizeToolCalls(s.toolCalls));
  }
  const planEmpty = plan.status === "failed" || planned.size === 0;
  if (planEmpty) logger.warn({ status: plan.status }, "Custom report: no usable plan; using the default data for every section");

  // ── Write ──
  let done = 0;
  let emptySections = 0;
  const writeSection = async (section: TemplateSection): Promise<string> => {
    const calls = planned.get(section.index) ?? [{ tool: "get_scan_summary", args: {} }];
    const results: Array<{ call: ToolCall; result: unknown }> = [{ call: { tool: "get_scan_summary", args: {} }, result: overview }];
    for (const c of calls) {
      if (c.tool === "get_scan_summary") continue;
      results.push({ call: c, result: await exec(c) });
    }
    let markdown = "";
    for (let round = 0; round < MAX_SECTION_ROUNDS; round++) {
      const canRequestData = round < MAX_SECTION_ROUNDS - 1;
      const raw = await call(
        WRITE_SYSTEM,
        [
          `REPORT: ${title}`,
          `SECTION: ${section.heading || "(introduction — text before the first heading)"}`,
          `SECTION TEMPLATE:\n${section.body.slice(0, GUIDANCE_CHARS) || "(no body — write what the heading calls for)"}`,
          instructions ? `AUDIENCE / TONE / EMPHASIS:\n${instructions}` : "",
          `canRequestData: ${canRequestData}`,
          `DATA:\n${formatToolResults(results, input.maskData)}`,
        ]
          .filter(Boolean)
          .join("\n\n"),
        WRITE_MAX_TOKENS,
      );
      const parsed = parseLlmJsonResponseDetailed<{ markdown?: unknown; toolCalls?: unknown }>(raw, {}).value;
      const more = canRequestData ? sanitizeToolCalls(parsed.toolCalls) : [];
      if (more.length > 0 && typeof parsed.markdown !== "string") {
        await progress(-1, "", `"${section.heading || "Introduction"}": fetching ${more.map((m) => m.tool).join(", ")}`);
        for (const c of more) results.push({ call: c, result: await exec(c) });
        continue;
      }
      markdown = typeof parsed.markdown === "string" ? stripRawHtml(parsed.markdown).trim() : "";
      break;
    }
    done++;
    if (!markdown) {
      emptySections++;
      markdown = "_This section could not be generated from the scan data._";
    }
    await progress(
      15 + Math.round((done / sections.length) * 75),
      `Writing sections (${done}/${sections.length})`,
      `Wrote "${section.heading || "Introduction"}"`,
    );
    return stripRepeatedHeading(markdown, section.heading);
  };

  await progress(15, `Writing sections (0/${sections.length})`);
  const bodies = await mapPool(sections, SECTION_CONCURRENCY, writeSection);
  if (emptySections === sections.length) {
    throw new ReportFailure(
      "The AI provider returned no usable content for any section. Check the provider, model and key under Settings → LLM, then generate the report again.",
    );
  }

  // ── Assemble + ground ──
  await progress(92, "Checking finding references");
  const assembled = sections
    .map((s, i) => (s.heading ? `${"#".repeat(Math.max(2, s.level))} ${s.heading}\n\n${bodies[i]}` : bodies[i]))
    .join("\n\n");
  const grounding = groundReport(assembled, data);
  const appendix = referencedFindingsAppendix(grounding.cited, data.byRef);
  // The report is shared: mask anything secret-shaped the model echoed, even
  // when prompt masking is switched off for this instance.
  const masker = createRedactionSession();
  const markdown = masker.redact([grounding.markdown, appendix].filter(Boolean).join("\n\n"));

  return { title, markdown, grounding: { ...grounding, emptySections }, llmCalls };
}

/** Run one queued report end to end, recording progress on its row. */
export async function runCustomReport(reportId: string): Promise<void> {
  const report = await prisma.customReport.findUnique({
    where: { id: reportId },
    include: { scan: { select: { id: true, project: { select: { name: true } } } } },
  });
  if (!report || report.status !== "QUEUED") return;
  const claimed = await prisma.customReport.updateMany({
    where: { id: reportId, status: "QUEUED" },
    data: { status: "RUNNING", startedAt: new Date(), progress: 2, stage: "Starting" },
  });
  if (claimed.count === 0) return;

  const steps: ReportStep[] = [];
  let lastProgress = 2;
  let lastStage = "Starting";
  const record = async (p: number, stage: string, step?: string) => {
    if (p >= 0) lastProgress = Math.max(lastProgress, Math.min(100, p));
    if (stage) lastStage = stage;
    if (step) steps.push({ at: new Date().toISOString(), message: step.slice(0, 300) });
    await prisma.customReport
      .update({
        where: { id: reportId },
        data: { progress: lastProgress, stage: lastStage, steps: steps.slice(-MAX_STEPS_LOGGED) as unknown as Prisma.InputJsonValue },
      })
      .catch(() => undefined);
  };

  try {
    const orgSettings = await prisma.orgSettings.findUnique({ where: { organizationId: report.organizationId } });
    const config = getLlmConfig(orgSettings);
    if (!config.apiKey && config.provider !== "ollama") {
      throw new ReportFailure("No AI provider is configured. Set a provider and API key under Settings → LLM.");
    }
    await prisma.customReport.update({ where: { id: reportId }, data: { provider: config.provider, model: config.model } });

    await record(4, "Checking the AI provider", `Using ${config.provider} / ${config.model}`);
    const preflight = await checkLlmAvailable(config);
    if (!preflight.ok) {
      throw new ReportFailure(
        `The AI provider refused the request: ${config.provider} would not run ${config.model} because ${preflight.reason}. ` +
          "Fix the provider account or key under Settings → LLM, then generate the report again.",
      );
    }

    await record(6, "Loading scan data");
    const data = await loadReportData(report.scanId);
    if (!data) throw new ReportFailure("The scan no longer exists.");
    await record(8, "Loading scan data", `Loaded ${data.findings.length} finding(s) from scan ${data.scan.id}`);

    const client = createLlmClient(config);
    // One masking session for the whole report: the same secret gets the
    // same token in every section.
    const redaction = createRedactionSession();
    const llm: LlmCall = (system, user, maxTokens) =>
      analyzeWithLlm(client, config.model, system, user, { temperature: 0.2, maxTokens, redaction });

    const now = new Date();
    const out = await generateCustomReport({
      data,
      sources: createReportSources(report.scanId, data),
      template: report.templateSnapshot as unknown as TemplateSnapshot,
      extraInstructions: report.extraInstructions,
      llm,
      maskData: (json) => redaction.redact(json),
      now,
      onProgress: record,
    });

    const completedAt = new Date();
    const html = buildCustomReportHtml(out.markdown, {
      title: out.title,
      templateName: report.templateName,
      projectName: report.scan.project.name,
      scanId: report.scanId,
      generatedAt: completedAt,
      model: config.model,
    });
    const g = out.grounding;
    if (g.removed.length) steps.push({ at: new Date().toISOString(), message: `Removed ${g.removed.length} citation(s) of findings that do not exist in the scan` });
    await prisma.customReport.update({
      where: { id: reportId },
      data: {
        status: "COMPLETED",
        progress: 100,
        stage: "Completed",
        steps: steps.slice(-MAX_STEPS_LOGGED) as unknown as Prisma.InputJsonValue,
        title: out.title.slice(0, 300),
        markdown: out.markdown,
        html,
        llmCalls: out.llmCalls,
        grounding: {
          cited: g.cited.length,
          removed: g.removed,
          corrected: g.corrected.length,
          droppedLines: g.droppedLines,
          emptySections: g.emptySections,
          warnings: g.warnings,
        },
        completedAt,
        errorMessage: null,
      },
    });
    await writeAuditLog({
      organizationId: report.organizationId,
      userId: report.createdBy,
      action: "report.custom_completed",
      resource: "report",
      resourceId: reportId,
      details: { scanId: report.scanId, template: report.templateName, model: config.model, llmCalls: out.llmCalls, removedCitations: g.removed.length },
    });
  } catch (e) {
    const message = e instanceof ReportFailure ? e.message : `Report generation failed: ${errMsg(e)}`;
    logger.error({ reportId, err: errMsg(e) }, "Custom report failed");
    await prisma.customReport
      .update({
        where: { id: reportId },
        data: { status: "FAILED", stage: "Failed", errorMessage: message.slice(0, 2000), completedAt: new Date() },
      })
      .catch(() => undefined);
    await writeAuditLog({
      organizationId: report.organizationId,
      userId: report.createdBy,
      action: "report.custom_failed",
      resource: "report",
      resourceId: reportId,
      details: { scanId: report.scanId, template: report.templateName, error: message.slice(0, 500) },
    });
  }
}
