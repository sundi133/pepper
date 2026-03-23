import * as fs from "fs";
import * as path from "path";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { RawFinding, ScanContext, ScannerPlugin, Chunk } from "../types";
import { chunkFile } from "../sast/chunker";
import { ZERO_DAY_SYSTEM_PROMPT } from "./prompts";
import { selectZeroDayFiles } from "./file-prioritizer";
import {
  FILE_EXTENSIONS,
  SKIP_DIRECTORIES,
  BINARY_EXTENSIONS,
  MAX_CHUNK_TOKENS,
  CHUNK_OVERLAP_TOKENS,
  OLLAMA_MAX_CHUNK_TOKENS,
  OLLAMA_CHUNK_OVERLAP_TOKENS,
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
} from "@/lib/constants";
import { logger } from "@/lib/logger";

interface ZeroDayLlmFinding {
  title: string;
  severity: string;
  category?: string;
  description: string;
  startLine: number;
  endLine: number;
  cweId?: string;
  confidence?: number;
  attackVector?: string;
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
    const chunkTokens = isOllama ? OLLAMA_MAX_CHUNK_TOKENS : MAX_CHUNK_TOKENS;
    const overlapTokens = isOllama
      ? OLLAMA_CHUNK_OVERLAP_TOKENS
      : CHUNK_OVERLAP_TOKENS;
    const maxResponseTokens = isOllama
      ? OLLAMA_MAX_RESPONSE_TOKENS
      : LLM_MAX_RESPONSE_TOKENS;

    // Only analyze high-priority files
    const targetFiles = selectZeroDayFiles(ctx.fileList);
    if (targetFiles.length === 0) return [];

    logger.info(
      { fileCount: targetFiles.length },
      "Zero-day scanner: analyzing priority files",
    );
    ctx.onProgress?.(
      `Zero-Day: analyzing ${targetFiles.length} priority files...`,
    );

    const findings: RawFinding[] = [];
    const maxConcurrency = parseInt(process.env.MAX_LLM_CONCURRENCY || "2");
    const chunks: Chunk[] = [];

    for (const filePath of targetFiles) {
      if (ctx.signal?.aborted) break;

      const ext = path.extname(filePath).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;
      if (!FILE_EXTENSIONS[ext]) continue;

      const parts = filePath.split(path.sep);
      if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;

      const fullPath = path.join(ctx.workDir, filePath);
      try {
        const content = fs.readFileSync(fullPath, "utf-8");
        if (content.trim().length === 0) continue;
        chunks.push(
          ...chunkFile(content, filePath, chunkTokens, overlapTokens),
        );
      } catch {
        continue;
      }
    }

    // Process chunks with concurrency limit
    for (let i = 0; i < chunks.length; i += maxConcurrency) {
      if (ctx.signal?.aborted) break;

      const batch = chunks.slice(i, i + maxConcurrency);
      const results = await Promise.allSettled(
        batch.map((chunk) =>
          analyzeChunk(
            client,
            ctx.orgSettings.llmModel,
            chunk,
            maxResponseTokens,
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
        await ctx.onBatchFindings("ZERO_DAY", batchFindings);
      }
    }

    ctx.onProgress?.(
      `Zero-Day: ${findings.length} potential novel vulnerabilities found`,
    );
    return findings;
  },
};

async function analyzeChunk(
  client: ReturnType<typeof createLlmClient>,
  model: string,
  chunk: Chunk,
  maxResponseTokens: number,
): Promise<RawFinding[]> {
  const userContent = `File: ${chunk.filePath} (lines ${chunk.startLine}-${chunk.endLine})\n\n\`\`\`\n${chunk.content}\n\`\`\``;

  try {
    const raw = await analyzeWithLlm(
      client,
      model,
      ZERO_DAY_SYSTEM_PROMPT,
      userContent,
      { maxTokens: maxResponseTokens },
    );

    const parsed = parseLlmJsonResponse<{ findings: ZeroDayLlmFinding[] }>(
      raw,
      { findings: [] },
    );

    return (parsed.findings || [])
      .filter((f) => f.title && f.severity && (f.confidence ?? 0) >= 0.8)
      .map((f) => ({
        scanner: "ZERO_DAY" as const,
        severity: normalizeSeverity(f.severity),
        title: `[Zero-Day] ${f.title}`,
        description: [
          f.description,
          f.attackVector ? `\nAttack Vector: ${f.attackVector}` : "",
          f.category ? `\nCategory: ${f.category}` : "",
          f.recommendation ? `\nRecommendation: ${f.recommendation}` : "",
        ].join(""),
        filePath: chunk.filePath,
        startLine: f.startLine,
        endLine: f.endLine,
        cweId: f.cweId,
        confidence: f.confidence ?? 0.8,
        ruleId: `ZD-${f.cweId || "NOVEL"}`,
      }));
  } catch (err) {
    logger.error(
      { err, filePath: chunk.filePath },
      "Zero-day chunk analysis failed",
    );
    return [];
  }
}

function normalizeSeverity(s: string): RawFinding["severity"] {
  const upper = s.toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(upper)) {
    return upper as RawFinding["severity"];
  }
  return "MEDIUM";
}
