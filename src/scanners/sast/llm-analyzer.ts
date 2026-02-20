import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { Chunk, RawFinding, ScanContext } from "../types";
import { chunkFile } from "./chunker";
import * as fs from "fs";
import * as path from "path";
import {
  FILE_EXTENSIONS,
  SKIP_DIRECTORIES,
  BINARY_EXTENSIONS,
  MAX_CHUNK_TOKENS,
  CHUNK_OVERLAP_TOKENS,
  OLLAMA_MAX_CHUNK_TOKENS,
  OLLAMA_CHUNK_OVERLAP_TOKENS,
} from "@/lib/constants";
import { logger } from "@/lib/logger";

const SYSTEM_PROMPT = `You are an expert security code reviewer. Analyze the following code for security vulnerabilities.

For each vulnerability found, provide a JSON response with this structure:
{
  "findings": [
    {
      "title": "Brief vulnerability title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "Detailed description of the vulnerability and its impact",
      "startLine": <line number where the issue starts>,
      "endLine": <line number where the issue ends>,
      "cweId": "CWE-XXX",
      "confidence": <0.0 to 1.0>,
      "recommendation": "How to fix this issue"
    }
  ]
}

Focus on:
- Injection vulnerabilities (SQL, command, LDAP, XSS, XXE)
- Authentication and authorization flaws
- Cryptographic weaknesses
- Sensitive data exposure
- Security misconfigurations
- Insecure deserialization
- Broken access control
- Server-side request forgery (SSRF)
- Mass assignment vulnerabilities

If no vulnerabilities are found, return: {"findings": []}
Be precise with line numbers. Only report genuine security issues with HIGH confidence.`;

interface LlmFinding {
  title: string;
  severity: string;
  description: string;
  startLine: number;
  endLine: number;
  cweId?: string;
  confidence?: number;
  recommendation?: string;
}

export async function runLlmSastScanner(
  ctx: ScanContext,
): Promise<RawFinding[]> {
  logger.info(
    {
      enableLlmSast: ctx.orgSettings.enableLlmSast,
      llmProvider: ctx.orgSettings.llmProvider,
      llmBaseUrl: ctx.orgSettings.llmBaseUrl,
      llmModel: ctx.orgSettings.llmModel,
    },
    "LLM SAST scanner invoked",
  );

  if (!ctx.orgSettings.enableLlmSast) {
    logger.warn("LLM SAST scanner skipped — enableLlmSast is false");
    return [];
  }

  const client = createLlmClient({
    provider: ctx.orgSettings.llmProvider,
    baseUrl: ctx.orgSettings.llmBaseUrl,
    apiKey: ctx.orgSettings.llmApiKey,
    model: ctx.orgSettings.llmModel,
  });

  logger.info(
    {
      provider: ctx.orgSettings.llmProvider,
      baseUrl: ctx.orgSettings.llmBaseUrl,
      model: ctx.orgSettings.llmModel,
    },
    "LLM client created",
  );

  const findings: RawFinding[] = [];
  const maxConcurrency = parseInt(process.env.MAX_LLM_CONCURRENCY || "2");
  const chunks: Chunk[] = [];

  // Pick chunk size based on provider — smaller chunks for Ollama/Qwen (CPU inference)
  const isOllama = ctx.orgSettings.llmProvider.toLowerCase() === "ollama";
  const chunkTokens = isOllama ? OLLAMA_MAX_CHUNK_TOKENS : MAX_CHUNK_TOKENS;
  const overlapTokens = isOllama
    ? OLLAMA_CHUNK_OVERLAP_TOKENS
    : CHUNK_OVERLAP_TOKENS;

  logger.info(
    { isOllama, chunkTokens, overlapTokens },
    "Chunk sizing for LLM provider",
  );

  // Collect all chunks from scannable files
  for (const filePath of ctx.fileList) {
    if (ctx.signal?.aborted) break;

    const fullPath = path.join(ctx.workDir, filePath);
    const ext = path.extname(filePath).toLowerCase();

    if (BINARY_EXTENSIONS.has(ext)) continue;
    if (!FILE_EXTENSIONS[ext]) continue;

    const parts = filePath.split(path.sep);
    if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;

    try {
      const content = fs.readFileSync(fullPath, "utf-8");
      if (content.trim().length === 0) continue;

      // Every file gets chunked into LLM-friendly pieces, no size limit
      chunks.push(...chunkFile(content, filePath, chunkTokens, overlapTokens));
    } catch {
      continue;
    }
  }

  ctx.onProgress?.(`LLM SAST: analyzing ${chunks.length} code chunks...`);

  // Process chunks with concurrency limit
  let succeeded = 0;
  let failed = 0;
  const totalBatches = Math.ceil(chunks.length / maxConcurrency);

  for (let i = 0; i < chunks.length; i += maxConcurrency) {
    if (ctx.signal?.aborted) break;

    const batchNum = Math.floor(i / maxConcurrency) + 1;
    const batch = chunks.slice(i, i + maxConcurrency);
    const results = await Promise.allSettled(
      batch.map((chunk) =>
        analyzeChunk(client, ctx.orgSettings.llmModel, chunk),
      ),
    );

    const batchFindings: RawFinding[] = [];
    for (const result of results) {
      if (result.status === "fulfilled") {
        batchFindings.push(...result.value);
        findings.push(...result.value);
        succeeded++;
      } else {
        failed++;
        logger.error(
          { err: result.reason },
          "LLM SAST chunk analysis rejected",
        );
      }
    }

    // Flush this batch's findings to DB immediately so they appear in UI
    if (batchFindings.length > 0 && ctx.onBatchFindings) {
      await ctx.onBatchFindings("SAST_LLM", batchFindings);
    }

    ctx.onProgress?.(
      `LLM SAST: batch ${batchNum}/${totalBatches} complete (${findings.length} findings so far)`,
    );
  }

  logger.info(
    { total: chunks.length, succeeded, failed, findings: findings.length },
    "LLM SAST analysis complete",
  );
  return findings;
}

async function analyzeChunk(
  client: ReturnType<typeof createLlmClient>,
  model: string,
  chunk: Chunk,
): Promise<RawFinding[]> {
  const userContent = `File: ${chunk.filePath} (lines ${chunk.startLine}-${chunk.endLine})\n\n\`\`\`\n${chunk.content}\n\`\`\``;

  try {
    logger.info(
      {
        filePath: chunk.filePath,
        startLine: chunk.startLine,
        endLine: chunk.endLine,
        model,
      },
      "Sending chunk to LLM",
    );
    const raw = await analyzeWithLlm(client, model, SYSTEM_PROMPT, userContent);
    logger.info(
      { filePath: chunk.filePath, responseLength: raw.length },
      "LLM response received",
    );
    const parsed = parseLlmJsonResponse<{ findings: LlmFinding[] }>(raw, {
      findings: [],
    });

    return (parsed.findings || [])
      .filter((f) => f.title && f.severity)
      .map((f) => ({
        scanner: "SAST_LLM" as const,
        severity: normalizeSeverity(f.severity),
        title: f.title,
        description: f.recommendation
          ? `${f.description}\n\nRecommendation: ${f.recommendation}`
          : f.description,
        filePath: chunk.filePath,
        startLine: f.startLine,
        endLine: f.endLine,
        cweId: f.cweId,
        confidence: f.confidence ?? 0.7,
        ruleId: `LLM-${f.cweId || "GENERIC"}`,
      }));
  } catch (err) {
    logger.error(
      {
        err,
        filePath: chunk.filePath,
        startLine: chunk.startLine,
        endLine: chunk.endLine,
      },
      "LLM SAST chunk analysis failed",
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
