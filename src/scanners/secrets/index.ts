import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanContext, ScannerPlugin } from "../types";
import { SECRET_PATTERNS } from "./patterns";
import { isHighEntropy, extractCandidateValues } from "./entropy";
import { maskSnippet } from "./masker";
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

        for (let lineNum = 0; lineNum < lines.length; lineNum++) {
          const line = lines[lineNum];

          // Pattern-based detection
          for (const pattern of SECRET_PATTERNS) {
            if (pattern.pattern.test(line)) {
              // Check allowlist
              if (pattern.allowlist?.some((al) => al.test(line))) {
                pattern.pattern.lastIndex = 0;
                continue;
              }

              const snippetStart = Math.max(0, lineNum - 1);
              const snippetEnd = Math.min(lines.length, lineNum + 2);
              const rawSnippet = lines
                .slice(snippetStart, snippetEnd)
                .map((l, i) => `${snippetStart + i + 1}: ${l}`)
                .join("\n");

              const maskedSnippet = maskSnippet(rawSnippet, [pattern.pattern]);

              findings.push({
                scanner: "SECRETS_PATTERN",
                severity: pattern.severity,
                title: pattern.title,
                description: pattern.description,
                filePath,
                startLine: lineNum + 1,
                endLine: lineNum + 1,
                snippet: maskedSnippet,
                ruleId: pattern.id,
                cweId: "CWE-798",
                confidence: 0.85,
                masked: true,
              });

              pattern.pattern.lastIndex = 0;
            }
            pattern.pattern.lastIndex = 0;
          }

          // Entropy-based detection
          const candidates = extractCandidateValues(line);
          for (const candidate of candidates) {
            if (isHighEntropy(candidate)) {
              // Check if already caught by pattern
              const alreadyCaught = findings.some(
                (f) =>
                  f.filePath === filePath &&
                  f.startLine === lineNum + 1 &&
                  f.scanner === "SECRETS_PATTERN",
              );
              if (alreadyCaught) continue;

              // Check if it's in a context suggesting it's a secret
              const contextKeywords =
                /(?:key|secret|token|password|credential|auth|api)/i;
              if (!contextKeywords.test(line)) continue;

              findings.push({
                scanner: "SECRETS_PATTERN",
                severity: "MEDIUM",
                title: "High-Entropy String in Secret Context",
                description:
                  "A high-entropy string was found in a context suggesting it may be a secret or credential.",
                filePath,
                startLine: lineNum + 1,
                endLine: lineNum + 1,
                snippet: `${lineNum + 1}: [MASKED HIGH-ENTROPY VALUE]`,
                ruleId: "ENTROPY_SECRET",
                cweId: "CWE-798",
                confidence: 0.6,
                masked: true,
              });
            }
          }
        }
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

    // First run pattern detection, then use LLM to classify
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

    // Re-tag as SECRETS_LLM
    return classified.map((f) => ({
      ...f,
      scanner: "SECRETS_LLM" as const,
      confidence: 0.95,
    }));
  },
};
