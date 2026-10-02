import * as fs from "fs";
import * as path from "path";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { RawFinding, ScanContext, ScannerPlugin, Chunk } from "../types";
import { chunkFile } from "../sast/chunker";
import { maskSecretValue, redactSensitiveText } from "../shared/evidence-redaction";
import { enrichFinding } from "../shared/finding-normalize";
import { SECRETS_AI_PROMPT } from "../shared/prompts";
import { applySeverityCalibration } from "@/lib/severity-calibration";
import { buildDeepRepoContext } from "../shared/repo-context";
import { buildRepoContextSummary } from "@/lib/llm-repo-context";
import { validateSecretCandidate, getEntropyLabel } from "./entropy-validator";
import { classifySecrets } from "./llm-classifier";
import { createRedactionSession } from "@/lib/llm-redaction";
import {
  PATTERN_DETECTORS,
  isCredibleSecretMatch,
  isInlineTestCode,
  isObviousNonSecret,
  isPrivateKeyBlock,
  isSecretScanCandidate,
} from "./patterns";
import {
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
import { llmExcludedPath } from "@/lib/llm-exclusions";

interface SecretLlmFinding {
  title: string;
  severity: string;
  credentialType: string;
  exposedValue: string;
  startLine: number;
  endLine: number;
  whyReal: string;
  provider?: string;
  impact: string;
  remediation: string;
  confidence: number;
}

export const secretsPatternScanner: ScannerPlugin = {
  name: "SECRETS_PATTERN",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

    for (const filePath of ctx.fileList) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;
      if (isSkippedPath(filePath)) continue;

      if (!isSecretScanCandidate(filePath, "pattern")) continue;

      const fullPath = path.join(ctx.workDir, filePath);
      let content: string;
      try {
        content = fs.readFileSync(fullPath, "utf-8");
        if (!content.trim()) continue;
      } catch {
        continue;
      }

      // First, check for multi-line patterns (like private keys)
      for (const [credentialType, config] of Object.entries(PATTERN_DETECTORS)) {
        if (credentialType.includes("KEY") && config.patterns.some(p => p.source.includes("BEGIN"))) {
          for (const patternSource of config.patterns) {
            if (!patternSource.source.includes("BEGIN")) continue;
            // Create fresh pattern to avoid .lastIndex state issues
            const pattern = new RegExp(patternSource.source, patternSource.flags || "gi");
            let match;
            while ((match = pattern.exec(content)) !== null) {
              const matchedValue = match[0];
              const lineNumber =
                content.substring(0, match.index).split("\n").length;

              // A header quoted in docs, an example or a format string is not a key.
              const headerLine = content.split("\n")[lineNumber - 1] ?? "";
              if (!isCredibleSecretMatch(credentialType, matchedValue, headerLine, filePath)) continue;
              if (!isPrivateKeyBlock(content, match.index)) continue;

              const masked = maskSecretValue(matchedValue.substring(0, 50) + "...");
              const base: RawFinding = lowerInTestCode(isInlineTestCode(filePath, content, match.index), applySeverityCalibration({
                scanner: "SECRETS_PATTERN",
                severity: config.severity,
                title: `${credentialType}: Exposed secret pattern detected`,
                description: "",
                filePath,
                startLine: lineNumber,
                endLine: lineNumber,
                snippet: `${lineNumber}: [MASKED ${credentialType}]`,
                ruleId: `SECRET-${credentialType}`,
                cweId: "CWE-798",
                confidence: 0.95,
                masked: true,
                metadata: {
                  credentialType,
                  maskedValue: masked,
                  category: "Secret",
                  weaknessClass: "Hardcoded Credential",
                  detectionMethod: "Pattern matching",
                },
              }));

              findings.push(
                enrichFinding(base, base.metadata as Record<string, unknown>, {
                  whatIsWrong: `${credentialType} exposed in source code`,
                  where: `${filePath}:${lineNumber}`,
                  whyExploitable: `This ${credentialType} can be used to authenticate to protected services`,
                  impact: "Unauthorized access to services and data",
                  fix: "Rotate the credential immediately and remove from repository history",
                  validation:
                    "Verify credential is no longer accessible from repository history",
                }),
              );
            }
          }
        }
      }

      // Then check single-line patterns
      const lines = content.split("\n");
      const lineOffsets: number[] = [];
      for (let i = 0, offset = 0; i < lines.length; offset += lines[i].length + 1, i++) lineOffsets.push(offset);
      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx];
        const lineNumber = lineIdx + 1;

        // Text already reported on this line: a later, more general detector doesn't report it again.
        const reportedSpans: Array<[number, number]> = [];
        for (const [credentialType, config] of Object.entries(PATTERN_DETECTORS)) {
          // Skip multi-line patterns for single-line scanning
          if (credentialType.includes("KEY") && config.patterns.some(p => p.source.includes("BEGIN"))) {
            continue;
          }

          for (const patternSource of config.patterns) {
            // Create fresh pattern to avoid .lastIndex state issues
            const pattern = new RegExp(patternSource.source, patternSource.flags || "g");
            let match;
            while ((match = pattern.exec(line)) !== null) {
              const matchedValue = match[0];

              // Skip placeholders, examples, templates and local defaults
              if (!isCredibleSecretMatch(credentialType, matchedValue, line, filePath)) continue;
              const span: [number, number] = [match.index, match.index + matchedValue.length];
              if (reportedSpans.some(([a, b]) => span[0] < b && a < span[1])) continue;
              reportedSpans.push(span);

              const masked = maskSecretValue(matchedValue);
              const inTest = isInlineTestCode(filePath, content, lineOffsets[lineIdx] + match.index);
              const base: RawFinding = lowerInTestCode(inTest, applySeverityCalibration({
                scanner: "SECRETS_PATTERN",
                severity: config.severity,
                title: `${credentialType}: Exposed secret pattern detected`,
                description: "",
                filePath,
                startLine: lineNumber,
                endLine: lineNumber,
                snippet: `${lineNumber}: [MASKED ${credentialType}]`,
                ruleId: `SECRET-${credentialType}`,
                cweId: "CWE-798",
                // A named setting holding key material is less certain than a provider's token format.
                confidence: credentialType === "GENERIC_SECRET" ? 0.72 : 0.95,
                masked: true,
                metadata: {
                  credentialType,
                  maskedValue: masked,
                  category: "Secret",
                  weaknessClass: "Hardcoded Credential",
                  detectionMethod: "Pattern matching",
                },
              }));

              findings.push(
                enrichFinding(base, base.metadata as Record<string, unknown>, {
                  whatIsWrong: `${credentialType} exposed in source code`,
                  where: `${filePath}:${lineNumber}`,
                  whyExploitable: `This ${credentialType} can be used to authenticate to protected services`,
                  impact: "Unauthorized access to services and data",
                  fix: "Rotate the credential immediately and remove from repository history",
                  validation:
                    "Verify credential is no longer accessible from repository history",
                }),
              );
            }
          }
        }
      }
    }

    if (findings.length > 0 && ctx.onBatchFindings) {
      await ctx.onBatchFindings("SECRETS_PATTERN", findings);
    }

    return findings;
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

      if (!isSecretScanCandidate(filePath, "llm")) continue;
      if (llmExcludedPath(filePath)) continue;

      const fullPath = path.join(ctx.workDir, filePath);
      try {
        const content = fs.readFileSync(fullPath, "utf-8");
        if (!content.trim()) continue;
        if (Buffer.byteLength(content, "utf8") > LLM_MAX_FILE_SIZE_BYTES) continue;
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

    // Deduplicate findings from overlapping chunks
    const deduped = new Map<string, RawFinding>();
    for (const f of findings) {
      const meta = f.metadata && typeof f.metadata === "object"
        ? (f.metadata as Record<string, unknown>)
        : {};
      const key = `${f.filePath}:${f.startLine}:${(meta.credentialType as string | undefined) ?? ""}`;
      const existing = deduped.get(key);
      if (!existing || (f.confidence ?? 0) > (existing.confidence ?? 0)) {
        deduped.set(key, f);
      }
    }
    const dedupedFindings = Array.from(deduped.values());

    if (dedupedFindings.length > 0 && ctx.orgSettings.enableLlmSecrets) {
      ctx.onProgress?.(`Secrets AI: classifying ${dedupedFindings.length} candidate(s)...`);
      const classified = await classifySecrets(dedupedFindings, {
        provider: ctx.orgSettings.llmProvider,
        baseUrl: ctx.orgSettings.llmBaseUrl,
        apiKey: ctx.orgSettings.llmApiKey,
        model: ctx.orgSettings.llmModel,
      });
      ctx.onProgress?.(`Secrets AI: ${classified.length} confirmed secret(s) after classification`);
      return classified;
    }

    ctx.onProgress?.(`Secrets AI: ${dedupedFindings.length} confirmed secret(s)`);
    return dedupedFindings;
  },
};

/** A secret in test-only code is one severity level lower, like one under a test path. */
function lowerInTestCode(inTest: boolean, finding: RawFinding): RawFinding {
  if (!inTest) return finding;
  const down = { CRITICAL: "HIGH", HIGH: "MEDIUM", MEDIUM: "LOW" } as const;
  const severity = down[finding.severity as keyof typeof down] ?? finding.severity;
  return { ...finding, severity, metadata: { ...(finding.metadata as object), inTestCode: true } };
}

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

  // Values are masked before the chunk goes to the model; the model reports
  // the token, and the real value is put back here, locally, for validation
  // and masking.
  const redaction = createRedactionSession();
  try {
    const raw = await analyzeWithLlm(client, model, SECRETS_AI_PROMPT, userContent, {
      maxTokens: LLM_MAX_RESPONSE_TOKENS,
      redaction,
    });
    const parsed = parseLlmJsonResponse<{ findings: SecretLlmFinding[] }>(raw, {
      findings: [],
    });
    for (const f of parsed.findings || []) {
      if (typeof f.exposedValue === "string") {
        f.exposedValue = redaction.restore(f.exposedValue.replace(/^\[?\[?(SECRET_\d+)\]?\]?$/, "[[$1]]"));
      }
    }

    return (parsed.findings || [])
      .filter(
        (f) =>
          f.title &&
          f.credentialType &&
          (f.confidence ?? 0) >= SECRETS_MIN_CONFIDENCE_DEFAULT &&
          // Whatever the model thought, a reference, template or stand-in is not a secret.
          !(typeof f.exposedValue === "string" && isObviousNonSecret(f.exposedValue)),
      )
      .map((f) => {
        // The LLM's free-text justification often quotes the literal secret
        // to explain "why it's real" — strip the exact known secret value
        // (most reliable, since we already have it in exposedValue) and run
        // generic secret-shape redaction on top, before this text is stored
        // in metadata, used in the finding description, or forwarded to the
        // second-pass classifier LLM.
        let safeWhyReal = f.whyReal;
        if (safeWhyReal) {
          if (f.exposedValue) {
            safeWhyReal = safeWhyReal.split(f.exposedValue).join("[REDACTED]");
          }
          safeWhyReal = redactSensitiveText(safeWhyReal);
        }

        // Entropy-based validation to reduce false positives
        const entropy = validateSecretCandidate(
          f.exposedValue || "****",
          f.credentialType,
          safeWhyReal,
        );

        // Adjust confidence based on entropy analysis
        let adjustedConfidence = f.confidence ?? 0.8;
        if (entropy.matchesKnownFormat) {
          adjustedConfidence = Math.min(1.0, adjustedConfidence + 0.15);
        } else if (!entropy.isHighEntropy) {
          // Lower confidence for low-entropy values
          adjustedConfidence = Math.min(
            adjustedConfidence,
            entropy.confidence * 0.9,
          );
        }

        // Filter out findings with very low entropy that don't match formats
        if (
          !entropy.matchesKnownFormat &&
          entropy.shannonEntropy < 3.0 &&
          adjustedConfidence < 0.8
        ) {
          return null; // Will be filtered below
        }

        const masked = maskSecretValue(f.exposedValue || "****");
        const base: RawFinding = applySeverityCalibration({
          scanner: "SECRETS_LLM",
          severity: (f.severity?.toUpperCase() === "CRITICAL" || !f.severity) ? "CRITICAL" : "HIGH",
          title: `${f.credentialType}: ${f.title}`,
          description: "",
          filePath: chunk.filePath,
          startLine: f.startLine,
          endLine: f.endLine || f.startLine,
          snippet: `${f.startLine}: [MASKED ${f.credentialType}]`,
          ruleId: `SECRET-${f.credentialType.toUpperCase().replace(/\s+/g, "_")}`,
          cweId: "CWE-798",
          confidence: adjustedConfidence,
          masked: true,
          metadata: {
            credentialType: f.credentialType,
            maskedValue: masked,
            provider: f.provider,
            category: "Secret",
            weaknessClass: "Hardcoded Credential",
            evidence: safeWhyReal,
            impact: f.impact,
            remediation: f.remediation,
            confidenceReason: safeWhyReal,
            entropy: {
              score: entropy.shannonEntropy,
              isHighEntropy: entropy.isHighEntropy,
              label: getEntropyLabel(entropy.shannonEntropy),
              matchesKnownFormat: entropy.matchesKnownFormat,
              detectedType: entropy.credentialType,
            },
          },
        });
        const endLine = f.endLine || f.startLine;
        const where =
          endLine !== f.startLine
            ? `${chunk.filePath}:${f.startLine}-${endLine}`
            : `${chunk.filePath}:${f.startLine}`;
        return enrichFinding(base, base.metadata as Record<string, unknown>, {
          whatIsWrong: `Exposed ${f.credentialType} in source code or configuration`,
          where,
          whyExploitable: safeWhyReal,
          impact: f.impact,
          fix: f.remediation,
          validation:
            "Rotate or revoke the credential and verify that it no longer appears in repository history scans",
        });
      })
      .filter((f): f is RawFinding => f !== null);
  } catch (err) {
    logger.error({ err, file: chunk.filePath }, "Secrets AI chunk failed");
    return [];
  }
}
