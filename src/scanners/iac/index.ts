import * as fs from "fs";
import * as path from "path";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { RawFinding, ScanContext, ScannerPlugin } from "../types";
import {
  detectIacFileType,
  SKIP_DIRECTORIES,
  MAX_FILE_SIZE_BYTES,
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
} from "@/lib/constants";
import { logger } from "@/lib/logger";

const IAC_SYSTEM_PROMPT = `You are an expert Infrastructure as Code (IaC) security auditor. Analyze the provided configuration file for security misconfigurations, hardcoded secrets, and compliance violations.

STRICT RULES:
1. Only report REAL, EXPLOITABLE misconfigurations — not style issues or best practices.
2. Confidence MUST be 0.7-1.0. Below 0.7: do NOT report.
3. Provide concrete impact and specific fix for each finding.

CHECK FOR THESE CATEGORIES:

**SECRETS & CREDENTIALS:**
- Hardcoded API keys, passwords, tokens, access keys in config
- Secrets not using secure secret management (Vault, SSM, K8s Secrets)
- Credentials visible in environment variables or logs

**ACCESS CONTROL & IAM:**
- Overly permissive IAM policies (*, admin, full access)
- Public access to private resources (S3, databases, ports)
- Missing authentication/authorization on endpoints

**ENCRYPTION & TRANSPORT:**
- Missing encryption at rest or in transit
- Disabled TLS verification
- Weak or deprecated cipher suites

**CONTAINER SECURITY:**
- Running as root (no USER directive in Dockerfile)
- Privileged containers or dangerous capabilities
- Docker socket mounted into containers
- Missing resource limits (memory, CPU)
- Using :latest tags (supply chain risk)

**NETWORK SECURITY:**
- Open ingress rules (0.0.0.0/0) on sensitive ports
- Missing network segmentation/policies
- Exposed management ports

**CI/CD PIPELINE SECURITY:**
- pull_request_target with checkout of untrusted PR code
- Third-party actions/orbs not pinned to SHA
- Secrets exposed in pipeline logs
- Missing branch protection for deployments

**M2M / WEBHOOK SECURITY:**
- Webhook endpoints without HMAC/signature verification
- Service account tokens without rotation or expiration
- Overprivileged OAuth scopes for integrations

For each finding respond with:
{
  "findings": [
    {
      "title": "Brief misconfiguration title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "What is misconfigured and why it's dangerous",
      "startLine": <line number>,
      "endLine": <line number>,
      "cweId": "CWE-XXX",
      "confidence": <0.7 to 1.0>,
      "recommendation": "Specific fix with code example"
    }
  ]
}

If no misconfigurations found, return: {"findings": []}
Do NOT report theoretical issues. Only report concrete misconfigurations.`;

interface IacLlmFinding {
  title: string;
  severity: string;
  description: string;
  startLine: number;
  endLine: number;
  cweId?: string;
  confidence?: number;
  recommendation?: string;
}

export const iacScanner: ScannerPlugin = {
  name: "IAC",
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

    // Collect IaC files
    const iacFiles: { filePath: string; iacType: string }[] = [];
    for (const filePath of ctx.fileList) {
      const parts = filePath.split(path.sep);
      if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;

      const iacType = detectIacFileType(filePath);
      if (iacType) {
        iacFiles.push({ filePath, iacType });
      }
    }

    if (iacFiles.length === 0) return [];

    logger.info({ fileCount: iacFiles.length }, "IaC scanner: analyzing files");
    ctx.onProgress?.(
      `IaC Security: analyzing ${iacFiles.length} configuration files...`,
    );

    const findings: RawFinding[] = [];
    const maxConcurrency = parseInt(process.env.MAX_LLM_CONCURRENCY || "2");

    for (let i = 0; i < iacFiles.length; i += maxConcurrency) {
      if (ctx.signal?.aborted) break;

      const batch = iacFiles.slice(i, i + maxConcurrency);
      const results = await Promise.allSettled(
        batch.map(async ({ filePath, iacType }) => {
          const fullPath = path.join(ctx.workDir, filePath);
          try {
            const stat = fs.statSync(fullPath);
            if (stat.size > MAX_FILE_SIZE_BYTES) return [];

            const content = fs.readFileSync(fullPath, "utf-8");
            if (content.trim().length === 0) return [];

            const userContent = `File: ${filePath}\nType: ${iacType}\n\n\`\`\`\n${content}\n\`\`\``;

            const raw = await analyzeWithLlm(
              client,
              ctx.orgSettings.llmModel,
              IAC_SYSTEM_PROMPT,
              userContent,
              { maxTokens: maxResponseTokens },
            );

            const parsed = parseLlmJsonResponse<{ findings: IacLlmFinding[] }>(
              raw,
              { findings: [] },
            );

            return (parsed.findings || [])
              .filter(
                (f) => f.title && f.severity && (f.confidence ?? 0) >= 0.7,
              )
              .map((f) => ({
                scanner: "IAC" as const,
                severity: normalizeSeverity(f.severity),
                title: f.title,
                description: f.recommendation
                  ? `${f.description}\n\nRecommendation: ${f.recommendation}`
                  : f.description,
                filePath,
                startLine: f.startLine,
                endLine: f.endLine,
                cweId: f.cweId,
                confidence: f.confidence ?? 0.7,
                ruleId: `IAC-${f.cweId || "MISC"}`,
                metadata: {
                  reportHints: compactObject({
                    rootCause: f.description,
                    secureFixExplanation: f.recommendation,
                    secureCodeExample: f.recommendation,
                  }),
                },
              }));
          } catch (err) {
            logger.error({ err, filePath }, "IaC analysis failed for file");
            return [];
          }
        }),
      );

      const batchFindings: RawFinding[] = [];
      for (const result of results) {
        if (result.status === "fulfilled") {
          batchFindings.push(...result.value);
          findings.push(...result.value);
        }
      }

      if (batchFindings.length > 0 && ctx.onBatchFindings) {
        await ctx.onBatchFindings("IAC", batchFindings);
      }
    }

    ctx.onProgress?.(
      `IaC Security: found ${findings.length} misconfigurations`,
    );
    return findings;
  },
};

function compactObject<T extends Record<string, unknown>>(value: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => entry !== undefined),
  ) as Partial<T>;
}

function normalizeSeverity(s: string): RawFinding["severity"] {
  const upper = s.toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(upper)) {
    return upper as RawFinding["severity"];
  }
  return "MEDIUM";
}
