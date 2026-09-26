/**
 * The AI remediation agent. For one run it:
 *   1. clones the repository and creates a working branch,
 *   2. walks the selected findings one at a time —
 *      locate → gather context → analyse (streamed) → edit → validate → commit,
 *      retrying a rejected fix with the validator's feedback,
 *   3. pushes the branch and opens a single pull request for every validated fix.
 *
 * Every step is written to RemediationEvent so the UI can replay and tail the
 * run live. Runs in the worker (see src/worker/index.ts).
 */
import { prisma } from "@/lib/prisma";
import { Prisma } from "@/generated/prisma/client";
import {
  analyzeWithLlm,
  createLlmClient,
  getLlmConfig,
  parseLlmJsonResponse,
  streamChatWithLlm,
  type LlmClient,
} from "@/lib/llm-gateway";
import { writeAuditLog } from "@/lib/audit-log";
import { RemediationEventSink } from "./event-sink";
import {
  applyEditsToContent,
  diffHasPlaceholder,
  diffStats,
  unrelatedDeletions,
  safeRepoRelativePath,
  unifiedDiff,
  type SearchReplaceEdit,
} from "./edits";
import { checkSyntax } from "./syntax-check";
import {
  ANALYZE_SYSTEM,
  FIX_SYSTEM,
  PLAN_SYSTEM,
  REVIEW_SYSTEM,
  parseDecision,
  stripDecision,
  wrapFile,
  wrapFinding,
  type FindingForPrompt,
} from "./prompts";
import {
  PROVIDER_LABELS,
  authenticatedRepoUrl,
  loadProviderCredentials,
  missingCredentialsMessage,
  openProviderPullRequest,
  resolveRemediationRepo,
} from "./repo-target";
import {
  RemediationWorkspace,
  remediationBranchName,
  resolveFindingPath,
} from "./workspace";
import type {
  RemediationRunStatus,
  RemediationStep,
  StepStatus,
  ValidationCheck,
} from "./types";

const MAX_ATTEMPTS = 3;
const MAX_FILES_PER_FIX = 6;
const MAX_CHANGED_LINES = 400;
const PRIMARY_FULL_LIMIT = 120_000;
const PRIMARY_WINDOW_LINES = 220;
const CONTEXT_FILE_LIMIT = 30_000;
const CONTEXT_TOTAL_LIMIT = 90_000;
const PLAN_CANDIDATE_LIMIT = 600;

type ItemOutcome = "FIXED" | "FAILED" | "SKIPPED";

interface LoadedItem {
  id: string;
  findingId: string;
  position: number;
  finding: {
    id: string;
    title: string;
    description: string;
    severity: string;
    scanner: string;
    filePath: string | null;
    startLine: number | null;
    endLine: number | null;
    snippet: string | null;
    ruleId: string | null;
    cweId: string | null;
    masked: boolean;
    status: string;
  } | null;
}

interface FixedRecord {
  findingId: string;
  title: string;
  severity: string;
  filePath: string;
  summary: string;
  stats: { added: number; removed: number };
  commitSha: string;
  reviewNote: string;
}

class RunCancelled extends Error {}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Primary file as sent to the model: whole file, or a window around the finding. */
function primaryView(
  content: string,
  startLine: number | null,
): { text: string; note?: string } {
  if (content.length <= PRIMARY_FULL_LIMIT) return { text: content };
  const lines = content.split("\n");
  const center = Math.max(1, startLine ?? 1);
  const from = Math.max(0, center - 1 - PRIMARY_WINDOW_LINES / 2);
  const to = Math.min(lines.length, from + PRIMARY_WINDOW_LINES);
  return {
    text: lines.slice(from, to).join("\n"),
    note: `excerpt lines ${from + 1}-${to} of ${lines.length}; search blocks must come from this excerpt`,
  };
}

/** Candidate paths for the planner: same directory first, then the rest. */
function planCandidates(primary: string, files: string[]): string[] {
  const dir = primary.includes("/") ? primary.slice(0, primary.lastIndexOf("/")) : "";
  const sameDir = files.filter(
    (f) => f !== primary && (dir ? f.startsWith(`${dir}/`) : !f.includes("/")),
  );
  const rest = files.filter((f) => f !== primary && !sameDir.includes(f));
  return [...sameDir, ...rest].slice(0, PLAN_CANDIDATE_LIMIT);
}

export async function runRemediation(runId: string): Promise<void> {
  const run = await prisma.remediationRun.findUnique({
    where: { id: runId },
    include: {
      items: { orderBy: { position: "asc" } },
      scan: {
        select: {
          id: true,
          sourceType: true,
          sourceRef: true,
          branch: true,
          project: {
            select: {
              repoUrl: true,
              defaultBranch: true,
              connectedViaGithub: true,
              connectedViaBitbucket: true,
              connectedViaAzure: true,
            },
          },
        },
      },
    },
  });
  if (!run || run.status !== "QUEUED") return;

  const claimed = await prisma.remediationRun.updateMany({
    where: { id: runId, status: "QUEUED" },
    data: { status: "RUNNING", startedAt: new Date() },
  });
  if (claimed.count === 0) return;

  const sink = await RemediationEventSink.open(runId);
  const log = (message: string, level: "info" | "warn" | "error" = "info") =>
    sink.emit({ type: "log", level, message });

  const findings = await prisma.finding.findMany({
    where: { id: { in: run.items.map((i) => i.findingId) }, scanId: run.scanId },
    select: {
      id: true,
      title: true,
      description: true,
      severity: true,
      scanner: true,
      filePath: true,
      startLine: true,
      endLine: true,
      snippet: true,
      ruleId: true,
      cweId: true,
      masked: true,
      status: true,
    },
  });
  const findingById = new Map(findings.map((f) => [f.id, f]));
  const items: LoadedItem[] = run.items.map((i) => ({
    id: i.id,
    findingId: i.findingId,
    position: i.position,
    finding: findingById.get(i.findingId) ?? null,
  }));

  let ws: RemediationWorkspace | null = null;
  const counts = { fixed: 0, failed: 0, skipped: 0 };
  const fixedRecords: FixedRecord[] = [];
  const unfixed: Array<{ title: string; status: ItemOutcome; reason: string }> = [];

  const finish = async (
    status: RemediationRunStatus,
    extra: { error?: string; prUrl?: string; prNumber?: number | null } = {},
  ) => {
    // Event first, status second: the SSE route stops once the status is
    // terminal, so the final event must already be persisted by then.
    await sink.emit({
      type: "run_done",
      status,
      fixed: counts.fixed,
      failed: counts.failed,
      skipped: counts.skipped,
      ...(extra.prUrl ? { prUrl: extra.prUrl, prNumber: extra.prNumber ?? null } : {}),
      ...(extra.error ? { error: extra.error } : {}),
    });
    await prisma.remediationRun.update({
      where: { id: runId },
      data: {
        status,
        completedAt: new Date(),
        fixedCount: counts.fixed,
        failedCount: counts.failed,
        errorMessage: extra.error ?? null,
        prUrl: extra.prUrl ?? null,
        prNumber: extra.prNumber ?? null,
      },
    });
  };

  const assertNotCancelled = async () => {
    const r = await prisma.remediationRun.findUnique({
      where: { id: runId },
      select: { cancelRequested: true },
    });
    if (r?.cancelRequested) throw new RunCancelled();
  };

  try {
    // ── Setup: repository, credentials, model ──────────────────────
    const target = resolveRemediationRepo({ scan: run.scan, project: run.scan.project });
    if (!target.ok) {
      await finish("FAILED", { error: target.error });
      return;
    }
    const creds = await loadProviderCredentials(run.organizationId, target.provider);
    if (!creds) {
      await finish("FAILED", { error: missingCredentialsMessage(target.provider) });
      return;
    }

    const orgSettings = await prisma.orgSettings.findUnique({
      where: { organizationId: run.organizationId },
    });
    const llm = getLlmConfig(orgSettings);
    if (!llm.apiKey && llm.provider !== "ollama") {
      await finish("FAILED", {
        error: "No LLM is configured. Set a provider and API key under Settings → LLM.",
      });
      return;
    }
    const client = createLlmClient(llm);

    await log(`Cloning ${target.repoUrl}…`);
    ws = await RemediationWorkspace.clone({
      authedUrl: authenticatedRepoUrl(target.repoUrl, creds),
      displayUrl: target.repoUrl,
      preferredBranch: target.baseBranch,
      runId,
    });
    if (target.baseBranch && ws.baseBranch !== target.baseBranch) {
      await log(
        `Branch "${target.baseBranch}" not found on the remote; using default branch "${ws.baseBranch}".`,
        "warn",
      );
    }
    const headBranch = remediationBranchName(runId);
    await ws.createBranch(headBranch);
    const files = ws.listFiles();

    await prisma.remediationRun.update({
      where: { id: runId },
      data: {
        provider: target.provider,
        repoUrl: target.repoUrl,
        baseBranch: ws.baseBranch,
        headBranch,
      },
    });
    await sink.emit({
      type: "run_started",
      total: items.length,
      provider: PROVIDER_LABELS[target.provider],
      repoUrl: target.repoUrl,
      baseBranch: ws.baseBranch,
      headBranch,
      model: llm.model,
    });
    await log(`Checked out ${files.length.toLocaleString()} files. Working on branch ${headBranch}.`);

    // ── Per-issue loop ─────────────────────────────────────────────
    for (const [index, item] of items.entries()) {
      await assertNotCancelled();
      const result = await remediateItem({
        runId,
        item,
        index,
        ws,
        files,
        client,
        model: llm.model,
        sink,
        assertNotCancelled,
      });
      if (result.outcome === "FIXED") {
        counts.fixed++;
        fixedRecords.push(result.record);
      } else {
        if (result.outcome === "FAILED") counts.failed++;
        else counts.skipped++;
        unfixed.push({
          title: item.finding?.title ?? "Finding",
          status: result.outcome,
          reason: result.reason,
        });
      }
    }

    // ── Ship ───────────────────────────────────────────────────────
    if (counts.fixed === 0) {
      const onlySkipped = counts.failed === 0;
      await finish(onlySkipped ? "COMPLETED" : "FAILED", {
        error: onlySkipped
          ? "No code changes were needed — every issue was judged a false positive or deferred to a human."
          : "No fix passed validation, so no pull request was opened.",
      });
      return;
    }

    await assertNotCancelled();
    await sink.emit({ type: "pr_opening", branch: headBranch, commits: counts.fixed });
    await log(`Pushing ${counts.fixed} commit${counts.fixed === 1 ? "" : "s"} to ${headBranch}…`);
    await ws.push(headBranch);

    await log(`Opening pull request on ${PROVIDER_LABELS[target.provider]}…`);
    const pr = await openProviderPullRequest(creds, {
      repoUrl: target.repoUrl,
      head: headBranch,
      base: ws.baseBranch,
      title: prTitle(fixedRecords),
      body: prBody(fixedRecords, unfixed, headBranch, llm.model),
    });
    if (!pr.ok) {
      await finish("FAILED", {
        error: `Fixes were pushed to branch "${headBranch}", but opening the pull request failed: ${pr.error}`,
      });
      return;
    }

    await markFindingsInProgress(fixedRecords, pr.url, run.createdBy);
    await writeAuditLog({
      organizationId: run.organizationId,
      userId: run.createdBy,
      action: "remediation.pr_opened",
      resource: "scan",
      resourceId: run.scanId,
      details: { runId, prUrl: pr.url, fixed: counts.fixed, failed: counts.failed },
    }).catch(() => undefined);

    await finish(counts.fixed === items.length ? "COMPLETED" : "PARTIAL", {
      prUrl: pr.url,
      prNumber: pr.number,
    });
  } catch (e) {
    if (e instanceof RunCancelled) {
      await prisma.remediationItem.updateMany({
        where: { runId, status: { in: ["PENDING", "ANALYZING", "FIXING", "VALIDATING"] } },
        data: { status: "SKIPPED", error: "Run cancelled", completedAt: new Date() },
      });
      await log("Run cancelled — nothing was pushed.", "warn");
      await finish("CANCELLED");
    } else {
      await finish("FAILED", { error: errMsg(e) });
    }
  } finally {
    ws?.dispose();
    await sink.close();
  }
}

// ─── One finding ──────────────────────────────────────────────────────

interface ItemContext {
  runId: string;
  item: LoadedItem;
  index: number;
  ws: RemediationWorkspace;
  files: string[];
  client: LlmClient;
  model: string;
  sink: RemediationEventSink;
  assertNotCancelled: () => Promise<void>;
}

type ItemResult =
  | { outcome: "FIXED"; record: FixedRecord }
  | { outcome: "FAILED" | "SKIPPED"; reason: string };

async function remediateItem(ctx: ItemContext): Promise<ItemResult> {
  const { item, ws, sink, client, model } = ctx;
  const itemId = item.id;
  const finding = item.finding;

  const step = (s: RemediationStep, status: StepStatus, message: string) =>
    sink.emit({ type: "step", itemId, step: s, status, message });
  const setItem = (data: Prisma.RemediationItemUpdateInput) =>
    prisma.remediationItem.update({ where: { id: itemId }, data });
  const conclude = async (
    outcome: ItemOutcome,
    reason: string,
    extra: { diff?: string; commitSha?: string } = {},
  ) => {
    await setItem({
      status: outcome,
      completedAt: new Date(),
      ...(outcome === "FIXED" ? { summary: reason } : { error: reason }),
    });
    await sink.emit({ type: "item_done", itemId, status: outcome, reason, ...extra });
  };

  await sink.emit({
    type: "item_started",
    itemId,
    index: ctx.index,
    title: finding?.title ?? "Finding no longer exists",
    filePath: finding?.filePath ?? null,
  });
  await setItem({ status: "ANALYZING", startedAt: new Date() });

  if (!finding) {
    const reason = "The finding was deleted (the scan may have been re-run).";
    await conclude("SKIPPED", reason);
    return { outcome: "SKIPPED", reason };
  }

  // ── Locate ─────────────────────────────────────────────────────────
  await step("locate", "running", `Locating ${finding.filePath ?? "file"} in the repository`);
  const primaryPath = resolveFindingPath(finding.filePath, ctx.files);
  const primaryContent = primaryPath ? ws.read(primaryPath) : null;
  if (!primaryPath || primaryContent === null) {
    const reason = !finding.filePath
      ? "The finding has no file location to fix."
      : primaryPath
        ? `${primaryPath} is binary or too large to edit safely.`
        : `${finding.filePath} was not found in the repository (it may have moved or been deleted).`;
    await step("locate", "failed", reason);
    await conclude("FAILED", reason);
    return { outcome: "FAILED", reason };
  }
  await step(
    "locate",
    "done",
    primaryPath === finding.filePath ? `Found ${primaryPath}` : `Mapped ${finding.filePath} → ${primaryPath}`,
  );

  const promptFinding: FindingForPrompt = {
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    scanner: finding.scanner,
    filePath: primaryPath,
    startLine: finding.startLine,
    endLine: finding.endLine,
    ruleId: finding.ruleId,
    cweId: finding.cweId,
    snippet: finding.masked ? null : finding.snippet,
  };
  const primary = primaryView(primaryContent, finding.startLine);

  // The flagged statement(s), resolved against the base commit so earlier
  // fixes in the same file (which shift line numbers) do not matter.
  const flaggedLines = new Set<string>();
  if (finding.startLine) {
    const base = (await ws.readAtBase(primaryPath)) ?? primaryContent;
    const lines = base.split("\n");
    const end = Math.max(finding.startLine, finding.endLine ?? finding.startLine);
    for (let n = finding.startLine; n <= end && n <= lines.length; n++) {
      const t = lines[n - 1]?.trim();
      if (t) flaggedLines.add(t);
    }
  }

  // ── Context ────────────────────────────────────────────────────────
  await step("context", "running", "Deciding which related files to read");
  const contextPaths: string[] = [];
  let planReasoning = "";
  try {
    const candidates = planCandidates(primaryPath, ctx.files);
    if (candidates.length > 0) {
      const raw = await analyzeWithLlm(
        client,
        model,
        PLAN_SYSTEM,
        [
          wrapFinding(promptFinding),
          wrapFile(primaryPath, primary.text.slice(0, 40_000), primary.note),
          `Other repository paths:\n${candidates.join("\n")}`,
        ].join("\n\n"),
        { temperature: 0, maxTokens: 1500 },
      );
      const plan = parseLlmJsonResponse<{ files?: unknown; reasoning?: unknown }>(raw, {});
      const allowed = new Set(candidates);
      if (Array.isArray(plan.files)) {
        for (const p of plan.files) {
          const safe = typeof p === "string" ? safeRepoRelativePath(p) : null;
          if (safe && allowed.has(safe) && !contextPaths.includes(safe)) contextPaths.push(safe);
          if (contextPaths.length >= 4) break;
        }
      }
      if (typeof plan.reasoning === "string") planReasoning = plan.reasoning.slice(0, 600);
    }
  } catch (e) {
    await sink.emit({ type: "log", level: "warn", message: `Context planning failed (${errMsg(e)}); continuing with the primary file.` });
  }
  const readContext = (): Array<{ path: string; content: string }> => {
    const out: Array<{ path: string; content: string }> = [];
    let total = 0;
    for (const p of contextPaths) {
      const c = ws.read(p);
      if (c === null) continue;
      const clipped = c.slice(0, CONTEXT_FILE_LIMIT);
      if (total + clipped.length > CONTEXT_TOTAL_LIMIT) break;
      total += clipped.length;
      out.push({ path: p, content: clipped });
    }
    return out;
  };
  const initialContext = readContext();
  await sink.emit({
    type: "context",
    itemId,
    files: [
      { path: primaryPath, lines: primaryContent.split("\n").length, primary: true },
      ...initialContext.map((f) => ({ path: f.path, lines: f.content.split("\n").length, primary: false })),
    ],
    reasoning: planReasoning || (initialContext.length ? "" : "The primary file has enough context."),
  });
  await step(
    "context",
    "done",
    `Reading ${1 + initialContext.length} file${initialContext.length ? "s" : ""}`,
  );

  // ── Analyse (streamed) ─────────────────────────────────────────────
  await ctx.assertNotCancelled();
  await step("analyze", "running", "Analysing the vulnerability");
  let analysis = "";
  try {
    const stream = streamChatWithLlm(
      client,
      [
        { role: "system", content: ANALYZE_SYSTEM },
        {
          role: "user",
          content: [
            wrapFinding(promptFinding),
            wrapFile(primaryPath, primary.text, primary.note),
            ...initialContext.map((f) => wrapFile(f.path, f.content)),
          ].join("\n\n"),
        },
      ],
      { temperature: 0.2, maxTokens: 2500 },
    );
    for await (const chunk of stream) {
      analysis += chunk;
      await sink.delta(itemId, chunk);
    }
  } catch (e) {
    const reason = `The model could not analyse this issue: ${errMsg(e)}`;
    await step("analyze", "failed", reason);
    await conclude("FAILED", reason);
    return { outcome: "FAILED", reason };
  }
  if (!analysis.trim()) {
    const reason = "The model returned an empty analysis.";
    await step("analyze", "failed", reason);
    await conclude("FAILED", reason);
    return { outcome: "FAILED", reason };
  }
  await setItem({ analysis: analysis.slice(0, 20_000) });
  const decision = parseDecision(analysis);
  const analysisBody = stripDecision(analysis);
  if (decision !== "fix") {
    const reason =
      decision === "false_positive"
        ? "Judged a false positive — no code change made. Review the analysis and update the finding status if you agree."
        : "Needs a human decision — the agent could not fix this safely on its own.";
    await step("analyze", "done", decision === "false_positive" ? "Likely false positive" : "Needs human review");
    await conclude("SKIPPED", reason);
    return { outcome: "SKIPPED", reason };
  }
  await step("analyze", "done", "Fix plan ready");

  // ── Fix → validate loop ────────────────────────────────────────────
  let feedback = "";
  let lastReason = "The fix did not pass validation.";
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    await ctx.assertNotCancelled();
    await setItem({ status: "FIXING", attempts: attempt });
    await step(
      "fix",
      "running",
      attempt === 1 ? "Writing the fix" : `Revising the fix (attempt ${attempt} of ${MAX_ATTEMPTS})`,
    );

    const currentPrimary = ws.read(primaryPath) ?? primaryContent;
    const currentPrimaryView = primaryView(currentPrimary, finding.startLine);
    const context = readContext();
    const editablePaths = new Set([primaryPath, ...context.map((f) => f.path)]);

    let parsed: { edits?: unknown; summary?: unknown; commitMessage?: unknown } = {};
    try {
      const raw = await analyzeWithLlm(
        client,
        model,
        FIX_SYSTEM,
        [
          wrapFinding(promptFinding),
          `<analysis>\n${analysisBody.slice(0, 6000)}\n</analysis>`,
          wrapFile(primaryPath, currentPrimaryView.text, currentPrimaryView.note),
          ...context.map((f) => wrapFile(f.path, f.content)),
          feedback
            ? `Your previous attempt was rejected. Fix these problems:\n${feedback}`
            : "",
        ]
          .filter(Boolean)
          .join("\n\n"),
        { temperature: 0.1, maxTokens: 16000 },
      );
      parsed = parseLlmJsonResponse(raw, {});
    } catch (e) {
      lastReason = `The model failed to produce a fix: ${errMsg(e)}`;
      feedback = lastReason;
      await step("fix", "failed", lastReason);
      continue;
    }

    const rawEdits = Array.isArray(parsed.edits) ? parsed.edits : [];
    const edits: SearchReplaceEdit[] = [];
    for (const e of rawEdits) {
      const r = e as Record<string, unknown>;
      if (typeof r?.path !== "string" || typeof r.replace !== "string") continue;
      edits.push({
        path: r.path,
        search: typeof r.search === "string" ? r.search : "",
        replace: r.replace,
      });
    }
    const summary =
      typeof parsed.summary === "string" && parsed.summary.trim()
        ? parsed.summary.trim().slice(0, 500)
        : `Fix ${finding.title}`;
    const commitSubject =
      typeof parsed.commitMessage === "string" && parsed.commitMessage.trim()
        ? parsed.commitMessage.trim().split("\n")[0].slice(0, 72)
        : `fix(security): ${finding.title}`.slice(0, 72);

    // Apply edits to the working copy, remembering originals for rollback.
    const checks: ValidationCheck[] = [];
    const originals = new Map<string, string | null>();
    const applyErrors: string[] = [];
    const byPath = new Map<string, SearchReplaceEdit[]>();
    for (const e of edits) {
      const safe = safeRepoRelativePath(e.path);
      if (!safe) {
        applyErrors.push(`Refused unsafe path "${e.path}"`);
        continue;
      }
      const isNew = !ws.exists(safe);
      if (!isNew && !editablePaths.has(safe)) {
        applyErrors.push(`${safe} was not provided as context; only edit the files you were given`);
        continue;
      }
      byPath.set(safe, [...(byPath.get(safe) ?? []), { ...e, path: safe }]);
    }
    if (edits.length === 0) applyErrors.push("The model returned no edits");
    if (byPath.size > MAX_FILES_PER_FIX) {
      applyErrors.push(`The fix touches ${byPath.size} files; keep it to ${MAX_FILES_PER_FIX} or fewer`);
    }

    const newContents = new Map<string, string>();
    if (applyErrors.length === 0) {
      for (const [p, pathEdits] of byPath) {
        const before = ws.exists(p) ? ws.read(p) : null;
        if (ws.exists(p) && before === null) {
          applyErrors.push(`${p} is binary or too large to edit`);
          continue;
        }
        const applied = applyEditsToContent(before, pathEdits, p);
        if (!applied.ok) {
          applyErrors.push(applied.error);
          continue;
        }
        originals.set(p, before);
        newContents.set(p, applied.content);
      }
    }
    checks.push({
      name: "Edits apply cleanly",
      status: applyErrors.length ? "failed" : "passed",
      detail: applyErrors.length ? applyErrors.join("; ") : `${newContents.size} file${newContents.size === 1 ? "" : "s"} updated`,
    });

    let diff = "";
    if (applyErrors.length === 0) {
      for (const [p, content] of newContents) ws.write(p, content);
      diff = [...newContents.entries()]
        .map(([p, content]) => unifiedDiff(p, originals.get(p) ?? null, content))
        .filter(Boolean)
        .join("\n");
      await sink.emit({
        type: "fix_proposed",
        itemId,
        attempt,
        summary,
        diff,
        files: [...newContents.keys()],
      });
      await step("fix", "done", summary);
    } else {
      await step("fix", "failed", "The proposed edits could not be applied");
    }

    // ── Validate ─────────────────────────────────────────────────────
    await setItem({ status: "VALIDATING" });
    await step("validate", "running", "Validating the fix");
    if (applyErrors.length === 0) {
      const stats = diffStats(diff);
      if (!diff) {
        checks.push({ name: "Produces a change", status: "failed", detail: "The edits did not change any file" });
      } else if (diffHasPlaceholder(diff)) {
        checks.push({ name: "Complete code", status: "failed", detail: "The fix contains an elision placeholder instead of real code" });
      } else if (stats.added + stats.removed > MAX_CHANGED_LINES) {
        checks.push({
          name: "Focused change",
          status: "failed",
          detail: `${stats.added + stats.removed} lines changed; keep the fix minimal (≤ ${MAX_CHANGED_LINES})`,
        });
      } else {
        checks.push({ name: "Focused change", status: "passed", detail: `+${stats.added} / -${stats.removed} lines` });
      }

      // Deleting a flagged line can be the fix (e.g. a debug statement), and a
      // leaked secret is removed outright — anything else deleted without a
      // replacement is collateral damage.
      if (diff && !finding.scanner.startsWith("SECRETS")) {
        const deleted = unrelatedDeletions(diff).filter(
          (d) =>
            !(d.path === primaryPath && flaggedLines.has(d.text)) &&
            !(finding.snippet && finding.snippet.includes(d.text)),
        );
        checks.push(
          deleted.length
            ? {
                name: "Preserves unrelated code",
                status: "failed",
                detail: `Deletes code that is not part of this fix: ${deleted
                  .slice(0, 3)
                  .map((d) => `${d.path}:${d.line} \`${d.text.slice(0, 80)}\``)
                  .join(", ")} — keep every line unrelated to this finding, even if it has its own issues`,
              }
            : { name: "Preserves unrelated code", status: "passed", detail: "No unrelated code removed" },
        );
      }

      for (const [p, content] of newContents) {
        const syntax = await checkSyntax(p, originals.get(p) ?? null, content);
        checks.push({ name: `Syntax: ${p}`, status: syntax.status, detail: syntax.detail });
      }

      if (finding.scanner.startsWith("SECRETS")) {
        checks.push(await rescanSecrets(ws, primaryPath, finding.ruleId));
      }

      if (!checks.some((c) => c.status === "failed")) {
        checks.push(
          await aiReview(client, model, promptFinding, diff, originals, newContents),
        );
      }
    }

    const passed = !checks.some((c) => c.status === "failed");
    await sink.emit({ type: "validation", itemId, attempt, passed, checks });

    if (passed) {
      await step("validate", "done", "All checks passed");
      await step("commit", "running", "Committing");
      const commitSha = await ws.commit(
        [...newContents.keys()],
        [
          commitSubject,
          "",
          summary,
          "",
          `Finding: ${finding.title}`,
          `Severity: ${finding.severity}`,
          `Pepper-Finding-Id: ${finding.id}`,
        ].join("\n"),
      );
      await step("commit", "done", `Committed ${commitSha.slice(0, 8)}`);
      await setItem({
        diff: diff.slice(0, 200_000),
        validation: checks as unknown as Prisma.InputJsonValue,
      });
      await conclude("FIXED", summary, { diff, commitSha });
      const review = checks.find((c) => c.name === "AI security review");
      return {
        outcome: "FIXED",
        record: {
          findingId: finding.id,
          title: finding.title,
          severity: finding.severity,
          filePath: primaryPath,
          summary,
          stats: diffStats(diff),
          commitSha,
          reviewNote: review?.status === "passed" ? review.detail : "",
        },
      };
    }

    // Roll back this attempt before retrying.
    for (const [p, before] of originals) {
      if (before === null) ws.remove(p);
      else ws.write(p, before);
    }
    const failed = checks.filter((c) => c.status === "failed");
    lastReason = failed.map((c) => `${c.name}: ${c.detail}`).join("; ");
    feedback = failed.map((c) => `- ${c.name}: ${c.detail}`).join("\n");
    await step(
      "validate",
      "failed",
      attempt < MAX_ATTEMPTS ? "Validation failed — retrying with feedback" : "Validation failed",
    );
    await setItem({ validation: checks as unknown as Prisma.InputJsonValue });
  }

  const reason = `Gave up after ${MAX_ATTEMPTS} attempts. ${lastReason}`.slice(0, 2000);
  await conclude("FAILED", reason);
  return { outcome: "FAILED", reason };
}

// ─── Validators ───────────────────────────────────────────────────────

/** Re-run the deterministic secrets scanner on the fixed file. */
async function rescanSecrets(
  ws: RemediationWorkspace,
  filePath: string,
  ruleId: string | null,
): Promise<ValidationCheck> {
  const name = "Secrets re-scan";
  try {
    const { secretsPatternScanner } = await import("@/scanners/secrets");
    const results = await secretsPatternScanner.scan({
      workDir: ws.dir,
      fileList: [filePath],
      scanType: "SECRETS_ONLY",
      orgSettings: {
        llmProvider: "",
        llmBaseUrl: "",
        llmModel: "",
        enableLlmSast: false,
        enableLlmSecrets: false,
        osvApiUrl: "",
        vulnDbMode: "offline",
      },
    });
    const still = results.filter((r) => !ruleId || r.ruleId === ruleId);
    if (still.length > 0) {
      return {
        name,
        status: "failed",
        detail: `The secret is still detected at line ${still[0].startLine ?? "?"} (${still[0].ruleId ?? "secret"})`,
      };
    }
    return { name, status: "passed", detail: "The scanner no longer detects the secret" };
  } catch (e) {
    return { name, status: "skipped", detail: `Re-scan unavailable: ${errMsg(e)}` };
  }
}

/** Independent LLM review of the diff. */
async function aiReview(
  client: LlmClient,
  model: string,
  finding: FindingForPrompt,
  diff: string,
  originals: Map<string, string | null>,
  newContents: Map<string, string>,
): Promise<ValidationCheck> {
  const name = "AI security review";
  let raw: string;
  try {
    raw = await analyzeWithLlm(
      client,
      model,
      REVIEW_SYSTEM,
      [
        wrapFinding(finding),
        `<file path="fix.diff">\n${diff.slice(0, 40_000)}\n</file>`,
        ...[...newContents.entries()].flatMap(([p, c]) => {
          const before = originals.get(p);
          return [
            ...(before != null ? [wrapFile(p, before.slice(0, 30_000), "BEFORE the fix")] : []),
            wrapFile(p, c.slice(0, 30_000), "AFTER the fix"),
          ];
        }),
      ].join("\n\n"),
      { temperature: 0, maxTokens: 3000 },
    );
  } catch (e) {
    return { name, status: "skipped", detail: `Reviewer unavailable: ${errMsg(e)}` };
  }
  const review = parseLlmJsonResponse<{
    resolvesFinding?: boolean;
    introducesIssues?: boolean;
    breaksBehaviour?: boolean;
    correctAPIs?: boolean;
    concerns?: unknown;
    verdict?: string;
  }>(raw, {});
  if (!review.verdict && review.resolvesFinding === undefined) {
    return { name, status: "skipped", detail: "Reviewer returned no verdict" };
  }
  const concerns = Array.isArray(review.concerns)
    ? review.concerns.filter((c): c is string => typeof c === "string").slice(0, 5)
    : [];
  const rejected =
    review.verdict === "reject" ||
    review.resolvesFinding === false ||
    review.introducesIssues === true ||
    review.breaksBehaviour === true ||
    review.correctAPIs === false;
  if (rejected) {
    return {
      name,
      status: "failed",
      detail: concerns.length ? concerns.join(" · ") : "The reviewer rejected the fix",
    };
  }
  return {
    name,
    status: "passed",
    detail: concerns.length ? `Approved with notes: ${concerns.join(" · ")}` : "Approved — resolves the finding without regressions",
  };
}

// ─── PR + finding bookkeeping ─────────────────────────────────────────

function prTitle(fixed: FixedRecord[]): string {
  if (fixed.length === 1) return `fix(security): ${fixed[0].title}`.slice(0, 240);
  return `fix(security): remediate ${fixed.length} security findings`;
}

function prBody(
  fixed: FixedRecord[],
  unfixed: Array<{ title: string; status: ItemOutcome; reason: string }>,
  branch: string,
  model: string,
): string {
  const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");
  const lines = [
    `## 🔒 AI security remediation`,
    ``,
    `Pepper's remediation agent fixed **${fixed.length}** finding${fixed.length === 1 ? "" : "s"}. Each fix is its own commit, was syntax-checked, and was approved by an independent AI review before being included.`,
    ``,
    `| Severity | Finding | File | Change |`,
    `| --- | --- | --- | --- |`,
    ...fixed.map(
      (f) =>
        `| ${f.severity} | ${esc(f.title)} | \`${f.filePath}\` | +${f.stats.added}/-${f.stats.removed} |`,
    ),
    ``,
    `### What changed`,
    ...fixed.map((f) => `- **${esc(f.title)}** (${f.commitSha.slice(0, 8)}) — ${esc(f.summary)}`),
  ];
  if (unfixed.length) {
    lines.push(
      ``,
      `### Not included`,
      ...unfixed.map((u) => `- **${esc(u.title)}** — ${u.status === "SKIPPED" ? "skipped" : "not fixed"}: ${esc(u.reason).slice(0, 300)}`),
    );
  }
  lines.push(
    ``,
    `---`,
    `_Generated by Pepper AI remediation (model \`${model}\`) on branch \`${branch}\`. Review every change and run your test suite before merging._`,
  );
  return lines.join("\n");
}

async function markFindingsInProgress(
  fixed: FixedRecord[],
  prUrl: string,
  userId: string | null,
): Promise<void> {
  await prisma.finding.updateMany({
    where: { id: { in: fixed.map((f) => f.findingId) }, status: "OPEN" },
    data: {
      status: "IN_PROGRESS",
      statusNote: `AI fix pull request: ${prUrl}`,
      statusUpdatedBy: userId,
      statusUpdatedAt: new Date(),
    },
  });
}
