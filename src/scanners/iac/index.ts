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
  LLM_MAX_FILE_SIZE_BYTES,
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
  MAX_LLM_CONCURRENCY,
  IAC_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";
import { logger } from "@/lib/logger";
import { buildRepoContextSummary } from "@/lib/llm-repo-context";

const IAC_SYSTEM_PROMPT = `You are an expert Infrastructure as Code (IaC) security auditor. Analyze the provided configuration file for security misconfigurations, hardcoded secrets, and compliance violations.

STRICT RULES:
1. Only report REAL, EXPLOITABLE misconfigurations — not style issues or best practices.
2. Confidence MUST be 0.65-1.0. Below 0.65: do NOT report.
3. Provide concrete impact and specific fix for each finding.

CHECK FOR THESE CATEGORIES:

**OWASP / CLOUD-NATIVE HIGH IMPACT RISKS:**
- Security misconfiguration that exposes management planes, metadata services, databases, queues, buckets, dashboards, or internal services
- Software/data integrity risks in CI/CD such as unpinned actions, mutable images, unsafe pull_request_target, unsigned artifacts, or deployment from untrusted branches
- Broken access control in IAM, RBAC, Kubernetes roles, service accounts, organization/project policies, and cross-account trust
- Sensitive data exposure through environment variables, build logs, artifacts, cache keys, state files, or IaC outputs
- AI/agent and automation risks: overprivileged CI tokens, MCP/tool credentials in jobs, LLM/API keys exposed to untrusted pull requests, autonomous deploy jobs without approval

**SECRETS & CREDENTIALS:**
- Hardcoded API keys, passwords, tokens, access keys in config
- Secrets not using secure secret management (Vault, SSM, K8s Secrets)
- Credentials visible in environment variables or logs
- Terraform state, pipeline artifacts, Docker build args, Helm values, or Kubernetes manifests leaking credentials

**ACCESS CONTROL & IAM:**
- Overly permissive IAM policies (*, admin, full access)
- Public access to private resources (S3, databases, ports)
- Missing authentication/authorization on endpoints
- Kubernetes ClusterRole/RoleBinding granting cluster-admin or wildcard verbs/resources to broad subjects
- Cloud role trust policies allowing external accounts, public principals, or broad service principals without conditions
- CI/CD service accounts with deploy/admin permissions available to pull requests or non-protected branches

**ENCRYPTION & TRANSPORT:**
- Missing encryption at rest or in transit
- Disabled TLS verification
- Weak or deprecated cipher suites
- Public load balancers, ingress, or service mesh routes lacking TLS or strict redirect
- Cloud storage, queues, disks, databases, backups, and logs without customer-managed or provider-managed encryption

**CONTAINER SECURITY:**
- Running as root (no USER directive in Dockerfile)
- Privileged containers or dangerous capabilities
- Docker socket mounted into containers
- Missing resource limits (memory, CPU)
- Using :latest tags (supply chain risk)
- Writable root filesystem, hostPath mounts, hostNetwork/hostPID/hostIPC, disabled seccomp/AppArmor/SELinux, or missing readOnlyRootFilesystem
- Images without digests, SBOM/provenance, or vulnerability gates in deployment workflows

**NETWORK SECURITY:**
- Open ingress rules (0.0.0.0/0) on sensitive ports
- Missing network segmentation/policies
- Exposed management ports
- Cloud metadata service exposure, missing IMDSv2, overly broad egress, unrestricted pod-to-pod traffic, or public database endpoints

**CI/CD PIPELINE SECURITY:**
- pull_request_target with checkout of untrusted PR code
- Third-party actions/orbs not pinned to SHA
- Secrets exposed in pipeline logs
- Missing branch protection for deployments
- Package install scripts running before trust is established
- Deployments triggered by untrusted tags, forks, comments, workflow_dispatch inputs, or mutable artifacts
- OIDC federation trust without repository, branch, environment, or audience restrictions

**M2M / WEBHOOK SECURITY:**
- Webhook endpoints without HMAC/signature verification
- Service account tokens without rotation or expiration
- Overprivileged OAuth scopes for integrations
- Replayable webhook/event workflows without timestamp, nonce, idempotency, or deduplication controls

For each finding respond with:
{
  "findings": [
    {
      "title": "Brief misconfiguration title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "Plain-language explanation: what is wrong, why it is risky in deployment, and who/what is affected. Do NOT paste Dockerfile/YAML/JSON blocks here, do NOT use a heading or label 'Code evidence', and do NOT repeat the same lines that are already in the file (the UI shows the file path and line numbers separately).",
      "startLine": <line number>,
      "endLine": <line number>,
      "cweId": "CWE-XXX",
      "confidence": <0.65 to 1.0>,
      "recommendation": "Concrete fix: short numbered or bulleted steps, optional one-line example directive only if it clarifies the fix (not a full file dump)"
    }
  ]
}

If no misconfigurations found, return: {"findings": []}
Do NOT report theoretical issues. Only report concrete misconfigurations.

The user message includes a REPOSITORY CONTEXT (paths only) from the full scan. Use it to notice multiple Dockerfiles, duplicate compose stacks, or sibling IaC roots — still cite only lines present in the provided file content.`;

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
      await ctx.waitIfPaused?.();
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

    const repoContextBlock = buildRepoContextSummary(ctx.fileList);
    const findings: RawFinding[] = [];
    const maxConcurrency = MAX_LLM_CONCURRENCY;

    for (let i = 0; i < iacFiles.length; i += maxConcurrency) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;

      const batch = iacFiles.slice(i, i + maxConcurrency);
      const results = await Promise.allSettled(
        batch.map(async ({ filePath, iacType }) => {
          const fullPath = path.join(ctx.workDir, filePath);
          try {
            const stat = fs.statSync(fullPath);
            if (stat.size > LLM_MAX_FILE_SIZE_BYTES) return [];

            const content = fs.readFileSync(fullPath, "utf-8");
            if (content.trim().length === 0) return [];
            const lines = content.split("\n");

            const userContent = `${repoContextBlock}\n--- CURRENT FILE ---\nFile: ${filePath}\nType: ${iacType}\n\n\`\`\`\n${content}\n\`\`\``;

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
                (f) =>
                  f.title &&
                  f.severity &&
                  (f.confidence ?? 0) >= IAC_MIN_CONFIDENCE_DEFAULT,
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
                snippet: buildSnippet(lines, f.startLine, f.endLine),
                cweId: f.cweId,
                confidence: f.confidence ?? IAC_MIN_CONFIDENCE_DEFAULT,
                ruleId: `IAC-${f.cweId || "MISC"}`,
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
  if (!startLine || startLine < 1) return undefined;
  const start = Math.max(0, startLine - 3);
  const end = Math.min(lines.length, (endLine || startLine) + 2);
  return lines
    .slice(start, end)
    .map((line, index) => `${start + index + 1}: ${line}`)
    .join("\n");
}
