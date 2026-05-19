import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanContext, ScannerPlugin } from "../types";
import { scanLinesForSecrets, secretHitsToRawFindings } from "./engine";
import { classifySecrets } from "./llm-classifier";
import {
  SKIP_DIRECTORIES,
  BINARY_EXTENSIONS,
  MAX_FILE_SIZE_BYTES,
} from "@/lib/constants";

export const secretsPatternScanner: ScannerPlugin = {
  name: "SECRETS_PATTERN",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

    for (const filePath of ctx.fileList) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;
      if (isGeneratedOrDatabasePath(filePath)) continue;

      const ext = path.extname(filePath).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;

      const parts = filePath.split(path.sep);
      if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;

      const fullPath = path.join(ctx.workDir, filePath);

      try {
        const stat = fs.statSync(fullPath);
        if (stat.size > MAX_FILE_SIZE_BYTES) continue;

        const content = fs.readFileSync(fullPath, "utf-8");
        const lines = content.split("\n");
        const hits = scanLinesForSecrets(lines, filePath);
        findings.push(...secretHitsToRawFindings(hits, filePath));
      } catch {
        continue;
      }
    }

    ctx.onProgress?.(
      `Secrets Pattern: found ${findings.length} potential secrets`,
    );
    return findings;
  },
};

function isGeneratedOrDatabasePath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  const basename = path.basename(normalized);
  if (/\.(sqlite|sqlite3|db|mdb|accdb)$/.test(basename)) return true;
  if (normalized.includes("/migrations/")) return true;
  if (normalized.includes("/__pycache__/")) return true;
  return false;
}

export const secretsLlmScanner: ScannerPlugin = {
  name: "SECRETS_LLM",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    if (!ctx.orgSettings.enableLlmSecrets) return [];

    const patternFindings = await secretsPatternScanner.scan(ctx);
    if (patternFindings.length === 0) return [];

    await ctx.waitIfPaused?.();
    ctx.onProgress?.(
      `Secrets LLM: classifying ${patternFindings.length} candidates...`,
    );

    const classified = await classifySecrets(patternFindings, {
      provider: ctx.orgSettings.llmProvider,
      baseUrl: ctx.orgSettings.llmBaseUrl,
      apiKey: ctx.orgSettings.llmApiKey,
      model: ctx.orgSettings.llmModel,
    });

    return classified.map((f) => ({
      ...f,
      scanner: "SECRETS_LLM" as const,
      confidence: Math.max(f.confidence ?? 0.85, 0.9),
    }));
  },
};
