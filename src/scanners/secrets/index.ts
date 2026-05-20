import * as fs from "fs";
import * as path from "path";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { RawFinding, ScanContext, ScannerPlugin, Chunk } from "../types";
import { chunkFile } from "../sast/chunker";
import { maskSecretValue } from "../shared/evidence-redaction";
import { enrichFinding } from "../shared/finding-normalize";
import { SECRETS_AI_PROMPT } from "../shared/prompts";
import { buildDeepRepoContext } from "../shared/repo-context";
import { buildRepoContextSummary } from "@/lib/llm-repo-context";
import {
  FILE_EXTENSIONS,
  SKIP_DIRECTORIES,
  BINARY_EXTENSIONS,
  MAX_CHUNK_TOKENS,
  CHUNK_OVERLAP_TOKENS,
  LLM_MAX_FILE_SIZE_BYTES,
  LLM_MAX_RESPONSE_TOKENS,
  MAX_LLM_CONCURRENCY,
  SECRETS_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";
import { logger } from "@/lib/logger";

const SECRET_SCAN_EXTENSIONS = new Set([
  ...Object.keys({
    ".js": 1,
    ".jsx": 1,
    ".ts": 1,
    ".tsx": 1,
    ".py": 1,
    ".go": 1,
    ".java": 1,
    ".rb": 1,
    ".php": 1,
    ".cs": 1,
    ".rs": 1,
    ".yml": 1,
    ".yaml": 1,
    ".json": 1,
    ".env": 1,
    ".toml": 1,
    ".tf": 1,
    ".sh": 1,
  }),
  ".env",
  ".pem",
  ".key",
]);

const CONFIG_BASENAMES = new Set([
  ".env",
  ".env.local",
  ".env.production",
  "credentials.json",
  "secrets.json",
  "config.json",
  "appsettings.json",
]);

interface SecretLlmFinding {
  title: string;
  severity: string;
  credentialType: string;
  maskedValue: string;
  startLine: number;
  endLine: number;
  whyReal: string;
  provider?: string;
  impact: string;
  remediation: string;
  confidence: number;
}

/** Pattern-based secrets scanner is quarantined — never emits findings. */
export const secretsPatternScanner: ScannerPlugin = {
  name: "SECRETS_PATTERN",
  async scan(): Promise<never[]> {
    return [];
  },
};

export const secretsLlmScanner: ScannerPlugin = {
  name: "SECRETS_LLM",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    if (!ctx.orgSettings.enableLlmSecrets) return [];

    const client = createLlmClient({
      provider: ctx.orgSettings.llmProvider,
      baseUrl: ctx.orgSettings.llmBaseUrl,
      apiKey: ctx.orgSettings.llmApiKey,
      model: ctx.orgSettings.llmModel,
    });

    const repoContext = buildDeepRepoContext(ctx.workDir, ctx.fileList);
    const pathSummary = buildRepoContextSummary(ctx.fileList);
    const chunks: Chunk[] = [];

    for (const filePath of ctx.fileList) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;
      if (isSkippedPath(filePath)) continue;

      const ext = path.extname(filePath).toLowerCase();
      const base = path.basename(filePath).toLowerCase();
      if (
        !SECRET_SCAN_EXTENSIONS.has(ext) &&
        !CONFIG_BASENAMES.has(base) &&
        !base.includes(".env")
      ) {
        continue;
      }

      const fullPath = path.join(ctx.workDir, filePath);
      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > LLM_MAX_FILE_SIZE_BYTES) continue;
        const content = fs.readFileSync(fullPath, "utf-8");
        if (!content.trim()) continue;
        chunks.push(
          ...chunkFile(content, filePath, MAX_CHUNK_TOKENS, CHUNK_OVERLAP_TOKENS),
        );
      } catch {
        continue;
      }
    }

    if (chunks.length === 0) return [];

    ctx.onProgress?.(
      `Secrets AI: reviewing ${chunks.length} chunks across source and config files...`,
    );

    const findings: RawFinding[] = [];
    const maxConcurrency = MAX_LLM_CONCURRENCY;

    for (let i = 0; i < chunks.length; i += maxConcurrency) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;

      const batch = chunks.slice(i, i + maxConcurrency);
      const results = await Promise.allSettled(
        batch.map((chunk) =>
          analyzeSecretChunk(
            client,
            ctx.orgSettings.llmModel,
            chunk,
            pathSummary,
            repoContext.summary,
          ),
        ),
      );

      const batchFindings: RawFinding[] = [];
      for (const result of results) {
        if (result.status === "fulfilled") {
          batchFindings.push(...result.value);
          findings.push(...result.value);
        }
      }
      if (batchFindings.length > 0 && ctx.onBatchFindings) {
        await ctx.onBatchFindings("SECRETS_LLM", batchFindings);
      }
    }

    ctx.onProgress?.(`Secrets AI: ${findings.length} confirmed secret(s)`);
    return findings;
  },
};

function isSkippedPath(filePath: string): boolean {
  const parts = filePath.split(path.sep);
  if (parts.some((p) => SKIP_DIRECTORIES.has(p))) return true;
  const ext = path.extname(filePath).toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) return true;
  if (/\.(sqlite|sqlite3|db)$/.test(filePath)) return true;
  return false;
}

async function analyzeSecretChunk(
  client: ReturnType<typeof createLlmClient>,
  model: string,
  chunk: Chunk,
  pathSummary: string,
  deepContext: string,
): Promise<RawFinding[]> {
  const userContent = `${pathSummary}\n${deepContext}\n--- FILE CHUNK ---\n${chunk.filePath} (lines ${chunk.startLine}-${chunk.endLine})\n\`\`\`\n${chunk.content}\n\`\`\``;

  try {
    const raw = await analyzeWithLlm(client, model, SECRETS_AI_PROMPT, userContent, {
      maxTokens: LLM_MAX_RESPONSE_TOKENS,
    });
    const parsed = parseLlmJsonResponse<{ findings: SecretLlmFinding[] }>(raw, {
      findings: [],
    });

    return (parsed.findings || [])
      .filter(
        (f) =>
          f.title &&
          f.credentialType &&
          (f.confidence ?? 0) >= SECRETS_MIN_CONFIDENCE_DEFAULT,
      )
      .map((f) => {
        const masked = maskSecretValue(f.maskedValue || "****");
        const base: RawFinding = {
          scanner: "SECRETS_LLM",
          severity: f.severity?.toUpperCase() === "HIGH" ? "HIGH" : "CRITICAL",
          title: `${f.credentialType}: ${f.title}`,
          description: "",
          filePath: chunk.filePath,
          startLine: f.startLine,
          endLine: f.endLine || f.startLine,
          snippet: `${f.startLine}: [MASKED ${f.credentialType}]`,
          ruleId: `SECRET-${f.credentialType.toUpperCase().replace(/\s+/g, "_")}`,
          cweId: "CWE-798",
          confidence: f.confidence,
          masked: true,
          metadata: {
            credentialType: f.credentialType,
            maskedValue: masked,
            provider: f.provider,
            category: "Secret",
            weaknessClass: "Hardcoded Credential",
            evidence: f.whyReal,
            impact: f.impact,
            remediation: f.remediation,
            confidenceReason: f.whyReal,
          },
        };
        return enrichFinding(base, base.metadata as Record<string, unknown>, {
          whatIsWrong: `Exposed ${f.credentialType} in source/config`,
          where: `${chunk.filePath}:${f.startLine}-${f.endLine || f.startLine}`,
          whyExploitable: f.whyReal,
          impact: f.impact,
          fix: f.remediation,
          validation: "Rotate credential and verify it no longer appears in repo history scans",
        });
      });
  } catch (err) {
    logger.error({ err, file: chunk.filePath }, "Secrets AI chunk failed");
    return [];
  }
}
