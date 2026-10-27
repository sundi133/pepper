import * as fs from "fs";
import * as path from "path";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { RawFinding, ScanContext, ScannerPlugin } from "../types";
import { buildDeepRepoContext } from "../shared/repo-context";
import { enrichFinding } from "../shared/finding-normalize";
import { applySeverityCalibration } from "@/lib/severity-calibration";
import { ZERO_DAY_SYSTEM_PROMPT } from "./prompts";
import { selectZeroDayFiles } from "./file-prioritizer";
import {
  FILE_EXTENSIONS,
  SKIP_DIRECTORIES,
  BINARY_EXTENSIONS,
  LLM_MAX_FILE_SIZE_BYTES,
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
  ZERO_DAY_MIN_CONFIDENCE_DEFAULT,
  ZERO_DAY_LLM_FILES,
} from "@/lib/constants";
import { logger } from "@/lib/logger";
import { llmExcludedPath } from "@/lib/llm-exclusions";
import { isPlainStaticHtml } from "../shared/extension-filters";
import {
  LOGIC_CONCURRENCY,
  LOGIC_ENDPOINT_MAP,
  LOGIC_MAP_IN_PROMPT,
  LOGIC_MAP_MAX_FILES,
  LOGIC_MAX_CANDIDATES,
  LOGIC_MAX_REGIONS,
  LOGIC_PATTERN_PACK,
} from "@/lib/constants";
import { buildLogicMap, endpointTable, runLogicChecks, type LogicOptions } from "./logic";
import { makeReasoningSink } from "../shared/reasoning-sink";

interface ZeroDayLlmFinding {
  title: string;
  severity: string;
  category?: string;
  description: string;
  filePath: string;
  startLine: number;
  endLine: number;
  cweId?: string;
  confidence?: number;
  attackVector?: string;
  stepsToReproduce?: string[];
  metadata?: Record<string, unknown>;
  recommendation?: string;
}

export const zeroDayScanner: ScannerPlugin = {
  name: "ZERO_DAY",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    if (!ctx.orgSettings.enableLlmSast) return [];

    const client = createLlmClient({
      provider: ctx.orgSettings.llmProvider,
      baseUrl: ctx.orgSettings.llmBaseUrl,
      apiKey: ctx.orgSettings.llmApiKey,
      model: ctx.orgSettings.llmModel,
    });

    const isOllama = ctx.orgSettings.llmProvider.toLowerCase() === "ollama";
    const maxResponseTokens = isOllama
      ? OLLAMA_MAX_RESPONSE_TOKENS
      : LLM_MAX_RESPONSE_TOKENS;

    // Logic passes (docs/LOGIC_FLAW_DETECTION_SPEC.md): build the verified
    // endpoint map first, so the main pass can use it, then run the checks
    // alongside the main pass.
    const logicOptions: LogicOptions = {
      workDir: ctx.workDir,
      fileList: ctx.fileList,
      client,
      model: ctx.orgSettings.llmModel,
      maxResponseTokens,
      endpointMap: LOGIC_ENDPOINT_MAP,
      patternPack: LOGIC_PATTERN_PACK,
      maxMapFiles: LOGIC_MAP_MAX_FILES,
      maxCandidates: LOGIC_MAX_CANDIDATES,
      maxRegions: LOGIC_MAX_REGIONS,
      concurrency: LOGIC_CONCURRENCY,
      minConfidence: ZERO_DAY_MIN_CONFIDENCE_DEFAULT,
      signal: ctx.signal,
      onProgress: ctx.onProgress,
    };
    const wantsMap = LOGIC_ENDPOINT_MAP || LOGIC_PATTERN_PACK || LOGIC_MAP_IN_PROMPT;
    const mapState = wantsMap ? await buildLogicMap(logicOptions) : null;
    const checks =
      mapState && (LOGIC_ENDPOINT_MAP || LOGIC_PATTERN_PACK)
        ? runLogicChecks(logicOptions, mapState)
        : Promise.resolve(null);
    const table = LOGIC_MAP_IN_PROMPT && mapState ? endpointTable(mapState.map) : "";

    // Stream + persist the model's reasoning for the cross-file pass. Opt-in in
    // the gateway, so a non-reasoning model/provider is unaffected.
    const reasoning = makeReasoningSink(ctx, "ZERO_DAY");
    const [main, logic] = await Promise.all([
      mainPass(ctx, client, maxResponseTokens, table, reasoning.onReasoning),
      checks,
    ]);
    await reasoning.finalize();
    const logicFindings = (logic?.findings ?? []).filter((f) => !coveredByMainPass(f, main));
    if (logicFindings.length > 0 && ctx.onBatchFindings) {
      await ctx.onBatchFindings("ZERO_DAY", logicFindings);
    }
    if (logicFindings.length > 0) {
      ctx.onProgress?.(`Logic review: ${logicFindings.length} confirmed authorization or logic finding(s)`);
    }
    return [...main, ...logicFindings];
  },
};

const AUTHZ_LIKE = /\b(?:CWE-(?:284|285|287|306|639|862|863|269|266|425|915|1220))\b|unauth|authori[sz]|access control|idor|bola|privilege|ownership|admin|role/i;

/**
 * A logic finding the main pass already reported: for a rule finding, an
 * authorization-like main finding inside the same handler; for a pattern
 * finding, a main finding on nearly the same line with the same CWE. The main
 * pass wrote it first, so its version is kept.
 */
export function coveredByMainPass(f: RawFinding, main: RawFinding[]): boolean {
  const meta = (f.metadata || {}) as Record<string, unknown>;
  const range = typeof meta.handlerRange === "string" ? /^(.*):(\d+)-(\d+)$/.exec(meta.handlerRange) : null;
  return main.some((m) => {
    if (m.filePath !== f.filePath || m.startLine == null || f.startLine == null) return false;
    if (range) {
      const inside = m.filePath === range[1] && m.startLine >= Number(range[2]) - 2 && m.startLine <= Number(range[3]) + 2;
      return inside && AUTHZ_LIKE.test(`${m.cweId ?? ""} ${m.title}`);
    }
    return Math.abs(m.startLine - f.startLine) <= 3 && !!m.cweId && m.cweId === f.cweId;
  });
}

/** The original cross-file pass over the highest-priority files, in one request. */
async function mainPass(
  ctx: ScanContext,
  client: ReturnType<typeof createLlmClient>,
  maxResponseTokens: number,
  endpointTableText: string,
  onReasoning?: (delta: string) => void,
): Promise<RawFinding[]> {
  {
    const repoContext = buildDeepRepoContext(ctx.workDir, ctx.fileList);
    const targetFiles = selectZeroDayFiles(ctx.fileList);
    if (targetFiles.length === 0) return [];

    const fileBundles: string[] = [];
    for (const filePath of targetFiles.slice(0, ZERO_DAY_LLM_FILES)) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;

      const ext = path.extname(filePath).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext) || !FILE_EXTENSIONS[ext]) continue;
      if (filePath.split(path.sep).some((p) => SKIP_DIRECTORIES.has(p))) continue;
      if (llmExcludedPath(filePath)) continue;

      try {
        const content = fs.readFileSync(
          path.join(ctx.workDir, filePath),
          "utf-8",
        );
        if (!content.trim()) continue;
        if (isPlainStaticHtml(filePath, content)) continue;
        fileBundles.push(`### ${filePath}\n\`\`\`\n${content.slice(0, 12000)}\n\`\`\``);
      } catch {
        continue;
      }
    }

    if (fileBundles.length === 0) return [];

    ctx.onProgress?.(
      `Zero-Day: cross-file exploit-chain analysis on ${fileBundles.length} files...`,
    );

    // The verified endpoint table replaces the regex route sample when there is one.
    const context = endpointTableText
      ? `${repoContext.summary.replace(/\nROUTE MAP \(sample\):\n(?: {2}.*\n)*/, "\n")}\n${endpointTableText}\n`
      : repoContext.summary;
    const userContent = `${context}\n\nHIGH-RISK FILES:\n${fileBundles.join("\n\n")}`;

    try {
      const raw = await analyzeWithLlm(
        client,
        ctx.orgSettings.llmModel,
        ZERO_DAY_SYSTEM_PROMPT,
        userContent,
        { maxTokens: maxResponseTokens, onReasoning },
      );

      const parsed = parseLlmJsonResponse<{ findings: ZeroDayLlmFinding[] }>(
        raw,
        { findings: [] },
      );

      const sentFilePaths = targetFiles.slice(0, ZERO_DAY_LLM_FILES);
      const dropped = { incomplete: 0, unknownFile: 0, lowConfidence: 0 };
      const candidates = (parsed.findings || []).flatMap((f) => {
        if (!f.title || !f.severity) {
          dropped.incomplete++;
          return [];
        }
        const filePath = resolveSentFile(f.filePath, sentFilePaths);
        if (!filePath) {
          dropped.unknownFile++;
          return [];
        }
        if ((f.confidence ?? 0) < ZERO_DAY_MIN_CONFIDENCE_DEFAULT) {
          dropped.lowConfidence++;
          return [];
        }
        return [{ ...f, filePath }];
      });
      if (dropped.incomplete + dropped.unknownFile + dropped.lowConfidence > 0) {
        logger.info(
          { returned: parsed.findings?.length ?? 0, kept: candidates.length, ...dropped },
          "Zero-day: dropped findings without a title, a file that was sent, or enough confidence",
        );
      }
      const findings = candidates
        .map((f) => {
          let snippet: string | undefined;
          try {
            const fileContent = fs.readFileSync(path.join(ctx.workDir, f.filePath), "utf-8");
            const fileLines = fileContent.split("\n");
            snippet = buildSnippet(fileLines, f.startLine, f.endLine);
          } catch {
            // Snippet is optional if file cannot be read
          }

          const base: RawFinding = applySeverityCalibration({
            scanner: "ZERO_DAY",
            severity: normalizeSeverity(f.severity),
            title: `[Zero-Day] ${f.title}`,
            description: f.description,
            filePath: f.filePath,
            startLine: f.startLine,
            endLine: f.endLine,
            snippet,
            cweId: f.cweId,
            confidence: f.confidence,
            ruleId: `ZD-${f.cweId || "CHAIN"}`,
            metadata: {
              ...(f.metadata || {}),
              category: f.category || "Novel",
              weaknessClass: f.category || "Business Logic",
              remediation:
                f.recommendation ||
                (f.metadata?.remediation as string) ||
                "Close the exploit chain per recommendation.",
            },
          });
          return enrichFinding(base, base.metadata as Record<string, unknown>, {
            whatIsWrong: f.title,
            where: `${f.filePath}:${f.startLine}`,
            whyExploitable: f.attackVector || f.description,
            attackPath: f.attackVector,
            stepsToReproduce: f.stepsToReproduce,
            impact: (f.metadata?.impact as string) || (f.attackVector ? `Exploitation of chain in ${f.filePath} leads to compromise.` : f.description),
            fix:
              f.recommendation ||
              (f.metadata?.remediation as string) ||
              "Close the exploit chain per recommendation.",
            validation: "Simulate exploit chain in staging environment to confirm vulnerability is neutralized.",
          });
        });

      if (findings.length > 0 && ctx.onBatchFindings) {
        await ctx.onBatchFindings("ZERO_DAY", findings);
      }

      ctx.onProgress?.(`Zero-Day: ${findings.length} validated chain finding(s)`);
      return findings;
    } catch (err) {
      logger.error({ err }, "Zero-day cross-file analysis failed");
      return [];
    }
  }
}

/**
 * The sent file a finding refers to. Models write the path from the `###`
 * header, sometimes with `./`, a leading folder, or only its tail, so an exact
 * match falls back to a unique suffix match. Unknown or ambiguous paths are
 * rejected: a finding must point at code the model actually saw.
 */
export function resolveSentFile(raw: unknown, sent: string[]): string | undefined {
  if (typeof raw !== "string" || !raw.trim()) return undefined;
  const norm = (p: string) => p.trim().replace(/\\/g, "/").replace(/^(?:\.\/|\/)+/, "");
  const want = norm(raw);
  const exact = sent.find((s) => norm(s) === want);
  if (exact) return exact;
  const matches = sent.filter((s) => {
    const have = norm(s);
    return have.endsWith(`/${want}`) || want.endsWith(`/${have}`);
  });
  return matches.length === 1 ? matches[0] : undefined;
}

function normalizeSeverity(s: string): RawFinding["severity"] {
  const upper = s.toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(upper)) {
    return upper as RawFinding["severity"];
  }
  return "MEDIUM";
}

function buildSnippet(
  lines: string[],
  startLine?: number,
  endLine?: number,
): string | undefined {
  if (!startLine || startLine < 1 || lines.length === 0) return undefined;
  const start = Math.max(0, startLine - 3);
  const end = Math.min(lines.length, (endLine || startLine) + 2);
  return lines
    .slice(start, end)
    .map((line, index) => `${start + index + 1}: ${line}`)
    .join("\n");
}
