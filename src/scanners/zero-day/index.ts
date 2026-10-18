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
        fileBundles.push(`### ${filePath}\n\`\`\`\n${content.slice(0, 12000)}\n\`\`\``);
      } catch {
        continue;
      }
    }

    if (fileBundles.length === 0) return [];

    ctx.onProgress?.(
      `Zero-Day: cross-file exploit-chain analysis on ${fileBundles.length} files...`,
    );

    const userContent = `${repoContext.summary}\n\nHIGH-RISK FILES:\n${fileBundles.join("\n\n")}`;

    try {
      const raw = await analyzeWithLlm(
        client,
        ctx.orgSettings.llmModel,
        ZERO_DAY_SYSTEM_PROMPT,
        userContent,
        { maxTokens: maxResponseTokens },
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
  },
};

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
