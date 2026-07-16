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
import { applySeverityCalibration } from "@/lib/severity-calibration";
import { buildDeepRepoContext } from "../shared/repo-context";
import { buildRepoContextSummary } from "@/lib/llm-repo-context";
import { validateSecretCandidate, getEntropyLabel } from "./entropy-validator";
import { classifySecrets } from "./llm-classifier";
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
  ".env.test",
  ".env.staging",
  ".env.ci",
  ".env.production.local",
  "credentials.json",
  "secrets.json",
  "config.json",
  "appsettings.json",
  "serviceAccountKey.json",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
]);

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

const PATTERN_DETECTORS: Record<string, { patterns: RegExp[]; severity: "CRITICAL" | "HIGH" }> = {
  AWS_ACCESS_KEY: {
    patterns: [
      /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
    ],
    severity: "CRITICAL",
  },
  AWS_SECRET_KEY: {
    patterns: [
      /\b([a-zA-Z0-9+/]{40})(==)?\b/g,
    ],
    severity: "CRITICAL",
  },
  GITHUB_TOKEN: {
    patterns: [
      /\b(ghp_|ghu_|gho_|ghs_)[a-zA-Z0-9_]{36,}\b/g,
      /\bgithub_pat_[a-zA-Z0-9_]{82}\b/g,
    ],
    severity: "CRITICAL",
  },
  GITLAB_TOKEN: {
    patterns: [
      /\bglpat-[a-zA-Z0-9_-]{20,}\b/g,
    ],
    severity: "CRITICAL",
  },
  SLACK_TOKEN: {
    patterns: [
      /\b(xox[bap])-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b/g,
    ],
    severity: "CRITICAL",
  },
  STRIPE_KEY: {
    patterns: [
      /\b(sk|pk)_(live|test)_[a-zA-Z0-9]{24,}\b/g,
    ],
    severity: "CRITICAL",
  },
  PRIVATE_KEY: {
    patterns: [
      /-----BEGIN (RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) PRIVATE KEY/gi,
    ],
    severity: "CRITICAL",
  },
  JWT_TOKEN: {
    patterns: [
      /\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.([a-zA-Z0-9_-]+)?\b/g,
    ],
    severity: "HIGH",
  },
  GOOGLE_API_KEY: {
    patterns: [
      /\bAIza[0-9A-Za-z_-]{35}\b/g,
    ],
    severity: "CRITICAL",
  },
  SENDGRID_KEY: {
    patterns: [
      /\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/g,
    ],
    severity: "CRITICAL",
  },
  TWILIO_KEY: {
    patterns: [
      /\bAC[a-zA-Z0-9]{32}\b/g,
    ],
    severity: "CRITICAL",
  },
  DATABRICKS_TOKEN: {
    patterns: [
      /\bdapi[a-z0-9]{32}[a-z0-9_-]+\b/gi,
    ],
    severity: "CRITICAL",
  },
  DATABASE_PASSWORD: {
    patterns: [
      /password\s*=\s*['"](.*?)['"]/gi,
      /db_password\s*:\s*['"](.*?)['"]/gi,
    ],
    severity: "HIGH",
  },
  AZURE_STORAGE_KEY: {
    patterns: [
      /DefaultEndpointsProtocol=https?;[^;]*AccountKey=[a-zA-Z0-9+/]{88}==/gi,
    ],
    severity: "CRITICAL",
  },
  AZURE_CONNECTION_STRING: {
    patterns: [
      /HostName=[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[a-zA-Z0-9+/=]+/gi,
    ],
    severity: "CRITICAL",
  },
  MONGODB_URI: {
    patterns: [
      /mongodb\+srv:\/\/[^:]+:[^@]+@[^\s"'`]+/gi,
      /mongodb:\/\/[^:]+:[^@]+@[^\s"'`]+/gi,
    ],
    severity: "CRITICAL",
  },
  FIREBASE_KEY: {
    patterns: [
      /AIza[0-9A-Za-z\-_]{35}/g,
      /AAAA[a-zA-Z0-9_-]{52}/g,
    ],
    severity: "CRITICAL",
  },
  HEROKU_API_KEY: {
    patterns: [
      /heroku[_]auth\s*=\s*['"]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?/gi,
      /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g,
    ],
    severity: "HIGH",
  },
  DIGITALOCEAN_TOKEN: {
    patterns: [
      /dop_v1_[a-z0-9]{64}/gi,
    ],
    severity: "CRITICAL",
  },
  GITHUB_OAUTH_TOKEN: {
    patterns: [
      /oauth_token\s*=\s*['"]?([a-f0-9]{32,40})['"]?/gi,
    ],
    severity: "CRITICAL",
  },
  REDIS_URL: {
    patterns: [
      /redis:\/\/:[^@]+@[^\s"'`]+(?::\d+)?/gi,
    ],
    severity: "HIGH",
  },
  SSH_PRIVATE_KEY: {
    patterns: [
      /-----BEGIN RSA PRIVATE KEY-----/gi,
      /-----BEGIN OPENSSH PRIVATE KEY-----/gi,
      /-----BEGIN EC PRIVATE KEY-----/gi,
      /-----BEGIN PRIVATE KEY-----/gi,
    ],
    severity: "CRITICAL",
  },
  NPM_TOKEN: {
    patterns: [
      /npm_[a-zA-Z0-9]{36}/g,
    ],
    severity: "CRITICAL",
  },
  DOCKER_CONFIG: {
    patterns: [
      /"auth"\s*:\s*"[a-zA-Z0-9+/]{20,}={0,2}"/gi,
    ],
    severity: "CRITICAL",
  },
  SLACK_WEBHOOK: {
    patterns: [
      /https:\/\/hooks\.slack\.com\/services\/[a-zA-Z0-9/]+/g,
    ],
    severity: "HIGH",
  },
  GRAFANA_API_KEY: {
    patterns: [
      /grafana_api_key\s*[=:]\s*['"]?([a-zA-Z0-9]{32,})['"]?/gi,
    ],
    severity: "HIGH",
  },
  NOTION_API_KEY: {
    patterns: [
      /secret_[a-z0-9]{40}/gi,
    ],
    severity: "CRITICAL",
  },
  MAILCHIMP_API_KEY: {
    patterns: [
      /[a-f0-9]{32}-us\d{1,2}/gi,
    ],
    severity: "HIGH",
  },
  OKTA_API_TOKEN: {
    patterns: [
      /00[a-zA-Z0-9_]{36}/g,
    ],
    severity: "CRITICAL",
  },
  OPENAI_API_KEY: {
    patterns: [
      /sk-[a-zA-Z0-9]{20,}/g,
      /sk-proj-[a-zA-Z0-9_]{20,}/g,
    ],
    severity: "CRITICAL",
  },
  ANTHROPIC_API_KEY: {
    patterns: [
      /sk-ant-[a-zA-Z0-9_]{20,}/g,
    ],
    severity: "CRITICAL",
  },
  SUPABASE_KEY: {
    patterns: [
      /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
    ],
    severity: "CRITICAL",
  },
  PRIVATE_KEY_FILE: {
    patterns: [
      /-----BEGIN (DSA|RSA|EC|OPENSSH|PGP) PRIVATE KEY(?:\sENCRYPTED)? -----/gi,
    ],
    severity: "CRITICAL",
  },
  API_KEY_ASSIGNMENT: {
    patterns: [
      /api[_-]?key\s*[:=]\s*['"]([\w\-\.]{20,})['"]/gi,
      /apikey\s*[:=]\s*['"]([\w\-\.]{20,})['"]/gi,
    ],
    severity: "HIGH",
  },
  SECRET_KEY_ASSIGNMENT: {
    patterns: [
      /secret[_-]?key\s*[:=]\s*['"]([\w\-\.]{20,})['"]/gi,
      /secretkey\s*[:=]\s*['"]([\w\-\.]{20,})['"]/gi,
    ],
    severity: "HIGH",
  },
};

export const secretsPatternScanner: ScannerPlugin = {
  name: "SECRETS_PATTERN",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];

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
          for (const pattern of config.patterns) {
            if (!pattern.source.includes("BEGIN")) continue;
            let match;
            pattern.lastIndex = 0;
            while ((match = pattern.exec(content)) !== null) {
              const matchedValue = match[0];
              const lineNumber =
                content.substring(0, match.index).split("\n").length;

              const masked = maskSecretValue(matchedValue.substring(0, 50) + "...");
              const base: RawFinding = applySeverityCalibration({
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
              });

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
      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx];
        const lineNumber = lineIdx + 1;

        for (const [credentialType, config] of Object.entries(PATTERN_DETECTORS)) {
          // Skip multi-line patterns for single-line scanning
          if (credentialType.includes("KEY") && config.patterns.some(p => p.source.includes("BEGIN"))) {
            continue;
          }

          for (const pattern of config.patterns) {
            let match;
            // Reset regex global state
            pattern.lastIndex = 0;
            while ((match = pattern.exec(line)) !== null) {
              const matchedValue = match[0];

              // Skip common false positives
              if (
                matchedValue.toLowerCase().includes("example") ||
                matchedValue.toLowerCase().includes("placeholder") ||
                matchedValue.toLowerCase().includes("test") ||
                /^(xxx|yyy|zzz|aaa|bbb|ccc|ddd|eee|fff|000|111|222)[\-_]/.test(
                  matchedValue,
                )
              ) {
                continue;
              }

              const masked = maskSecretValue(matchedValue);
              const base: RawFinding = applySeverityCalibration({
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
              });

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

    if (ctx.onScannerComplete) {
      await ctx.onScannerComplete("SECRETS_PATTERN", findings);
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

    if (findings.length > 0 && ctx.orgSettings.enableLlmSecrets) {
      ctx.onProgress?.(`Secrets AI: classifying ${findings.length} candidate(s)...`);
      const classified = await classifySecrets(findings, {
        provider: ctx.orgSettings.llmProvider,
        baseUrl: ctx.orgSettings.llmBaseUrl,
        apiKey: ctx.orgSettings.llmApiKey,
        model: ctx.orgSettings.llmModel,
      });
      ctx.onProgress?.(`Secrets AI: ${classified.length} confirmed secret(s) after classification`);
      if (ctx.onScannerComplete) {
        await ctx.onScannerComplete("SECRETS_LLM", classified);
      }
      return classified;
    }

    ctx.onProgress?.(`Secrets AI: ${findings.length} confirmed secret(s)`);
    if (ctx.onScannerComplete) {
      await ctx.onScannerComplete("SECRETS_LLM", findings);
    }
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
        // Entropy-based validation to reduce false positives
        const entropy = validateSecretCandidate(
          f.exposedValue || "****",
          f.credentialType,
          f.whyReal,
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
          severity: f.severity?.toUpperCase() === "HIGH" ? "HIGH" : "CRITICAL",
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
            evidence: f.whyReal,
            impact: f.impact,
            remediation: f.remediation,
            confidenceReason: f.whyReal,
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
          whyExploitable: f.whyReal,
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
