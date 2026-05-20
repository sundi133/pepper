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
import { ZERO_DAY_VALIDATION_PROMPT } from "../shared/prompts";
import { selectZeroDayFiles } from "./file-prioritizer";
import {
  FILE_EXTENSIONS,
  SKIP_DIRECTORIES,
  BINARY_EXTENSIONS,
  LLM_MAX_FILE_SIZE_BYTES,
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
  ZERO_DAY_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";
import { logger } from "@/lib/logger";

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
    for (const filePath of targetFiles.slice(0, 48)) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;

      const ext = path.extname(filePath).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext) || !FILE_EXTENSIONS[ext]) continue;
      if (filePath.split(path.sep).some((p) => SKIP_DIRECTORIES.has(p))) continue;

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
        ZERO_DAY_VALIDATION_PROMPT,
        userContent,
        { maxTokens: maxResponseTokens },
      );

      const parsed = parseLlmJsonResponse<{ findings: ZeroDayLlmFinding[] }>(
        raw,
        { findings: [] },
      );

      const findings = (parsed.findings || [])
        .filter(
          (f) =>
            f.title &&
            f.severity &&
            f.filePath &&
            (f.confidence ?? 0) >= ZERO_DAY_MIN_CONFIDENCE_DEFAULT,
        )
        .map((f) => {
          const base: RawFinding = {
            scanner: "ZERO_DAY",
            severity: normalizeSeverity(f.severity),
            title: `[Zero-Day] ${f.title}`,
            description: f.description,
            filePath: f.filePath,
            startLine: f.startLine,
            endLine: f.endLine,
            cweId: f.cweId,
            confidence: f.confidence,
            ruleId: `ZD-${f.cweId || "CHAIN"}`,
            metadata: {
              ...(f.metadata || {}),
              category: f.category || "Novel",
              weaknessClass: f.category,
            },
          };
          return enrichFinding(base, base.metadata as Record<string, unknown>, {
            whatIsWrong: f.title,
            where: `${f.filePath}:${f.startLine}`,
            whyExploitable: f.description,
            attackPath: f.metadata?.attackPath as string,
            fix:
              f.recommendation ||
              (f.metadata?.remediation as string) ||
              "Close the exploit chain per recommendation.",
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

function normalizeSeverity(s: string): RawFinding["severity"] {
  const upper = s.toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(upper)) {
    return upper as RawFinding["severity"];
  }
  return "MEDIUM";
}
