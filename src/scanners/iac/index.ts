import * as fs from "fs";
import * as path from "path";
import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { RawFinding, ScanContext, ScannerPlugin } from "../types";
import { groupIacStacks } from "./stacks";
import { enrichFinding } from "../shared/finding-normalize";
import { buildDeepRepoContext } from "../shared/repo-context";
import {
  SKIP_DIRECTORIES,
  LLM_MAX_FILE_SIZE_BYTES,
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
  MAX_LLM_CONCURRENCY,
  IAC_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";
import { logger } from "@/lib/logger";

const IAC_STACK_PROMPT = `You are a SENIOR IaC SECURITY AUDITOR performing DEEP STACK-LEVEL analysis.
Analyze ALL files in the stack together (Dockerfile+compose, Terraform module+vars, K8s+Helm, CI+deploy configs).
Mission: Find EVERY IaC misconfiguration that exposes the system to attack.

**SECURITY CHECKS (ALL FILES IN STACK):**

**TERRAFORM/CLOUD MISCONFIGURATIONS:**
- S3 buckets: Check Block Public Access settings, ACL (public-read), versioning/MFA delete missing
- Security Groups: CIDR 0.0.0.0/0 on sensitive ports (22, 3389, 1433), overly permissive
- RDS: PubliclyAccessible=true, no encryption, weak password policy, no backup retention
- Network ACLs: Missing ingress/egress rules, default allow, no rate limiting
- IAM: Overly permissive policies, * resources, no least privilege
- KMS: Customer managed keys not used, default encryption missing
- Secrets: Hardcoded in config — report to Secrets scanner, flag here as reference
- VPC: No private subnets, all resources in public subnets, missing NAT gateways

**KUBERNETES/CONTAINER ORCHESTRATION:**
- Admission controllers: PodSecurityPolicy missing, no webhook validation
- RBAC: ClusterAdmin role too broad, service account tokens accessible
- Network policies: None defined, all pods can communicate
- PersistentVolumes: hostPath mounts, no security context, world-readable
- Secrets: Stored in etcd without encryption, base64-encoded (not encrypted)
- Pod Security: Privileged containers, no securityContext, running as root
- Image: latest tags, public registries, no image scanning policies

**DOCKER/DOCKERFILE:**
- Already handled by container scanner, reference only if stack-level issue

**CI/CD PIPELINE:**
- Secrets in logs: CI/CD echoing secrets to build logs
- Credential storage: Secrets hardcoded in pipeline YAML
- Branch protection: No required reviews, force-push allowed to main
- Artifact storage: Storing secrets in build artifacts
- Deploy keys: SSH keys with no IP restrictions
- Webhook validation: No signature verification on webhooks

**NETWORK & COMMUNICATION:**
- No TLS/encryption: Services communicating over HTTP
- Self-signed certificates: In production without pinning
- DNS: No DNSSEC, no private DNS resolution
- Proxy/WAF: Missing or misconfigured

**SEVERITY ASSIGNMENT:**
- CRITICAL: Public exposure of sensitive service (DB, admin), root privilege, secrets in code/logs
- HIGH: Publicly accessible service without auth, overly permissive IAM, unencrypted data at rest
- MEDIUM: Deprecated TLS versions, weak encryption, verbose logging
- LOW: Best practices (resource tagging, backups), operational improvements
- INFO: Documentation, recommendations

Do NOT report hardcoded credential values here (Secrets scanner handles that) — reference them as "contains secrets, see Secrets findings"

Return JSON:
{
  "findings": [{
    "title": "<exact misconfiguration name>",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "description": "<line-by-line: what is wrong, what is exposed, how to exploit>",
    "filePath": "path/to/terraform/k8s/etc",
    "startLine": <int>,
    "endLine": <int>,
    "cweId": "CWE-16|CWE-284|CWE-416|CWE-668",
    "confidence": <0.80-1.0>,
    "recommendation": "<exact configuration fix with parameters>",
    "metadata": {
      "exposedAsset": "<what service/data is exposed>",
      "attackPath": "<how attacker exploits this>",
      "environment": "<prod|staging|dev>",
      "validationSteps": ["<test command or validation procedure>"],
      "remediation": "<step-by-step fix>"
    }
  }]
}`;

interface IacLlmFinding {
  title: string;
  severity: string;
  description: string;
  filePath: string;
  startLine: number;
  endLine: number;
  cweId?: string;
  confidence?: number;
  recommendation?: string;
  metadata?: Record<string, unknown>;
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

    const filteredList = ctx.fileList.filter(
      (fp) => !fp.split(path.sep).some((p) => SKIP_DIRECTORIES.has(p)),
    );
    const stacks = groupIacStacks(filteredList);
    if (stacks.length === 0) return [];

    const repoContext = buildDeepRepoContext(ctx.workDir, ctx.fileList);
    ctx.onProgress?.(`IaC: analyzing ${stacks.length} configuration stack(s)...`);

    const findings: RawFinding[] = [];
    const maxConcurrency = MAX_LLM_CONCURRENCY;

    for (let i = 0; i < stacks.length; i += maxConcurrency) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;

      const batch = stacks.slice(i, i + maxConcurrency);
      const results = await Promise.allSettled(
        batch.map((stack) =>
          analyzeStack(
            client,
            ctx,
            stack,
            repoContext.summary,
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
        await ctx.onBatchFindings("IAC", batchFindings);
      }
    }

    ctx.onProgress?.(`IaC: ${findings.length} stack-level misconfigurations`);
    return findings;
  },
};

async function analyzeStack(
  client: ReturnType<typeof createLlmClient>,
  ctx: ScanContext,
  stack: ReturnType<typeof groupIacStacks>[0],
  repoContextBlock: string,
  maxResponseTokens: number,
): Promise<RawFinding[]> {
  const parts: string[] = [];
  const lineMaps = new Map<string, string[]>();

  for (const { filePath, iacType } of stack.files) {
    try {
      const fullPath = path.join(ctx.workDir, filePath);
      const stat = fs.statSync(fullPath);
      if (stat.size > LLM_MAX_FILE_SIZE_BYTES) continue;
      const content = fs.readFileSync(fullPath, "utf-8");
      if (!content.trim()) continue;
      lineMaps.set(filePath, content.split("\n"));
      parts.push(
        `### ${filePath} (${iacType})\n\`\`\`\n${content}\n\`\`\``,
      );
    } catch {
      continue;
    }
  }

  if (parts.length === 0) return [];

  const userContent = `${repoContextBlock}\n\nSTACK: ${stack.id} (${stack.kind})\n${parts.join("\n\n")}`;

  try {
    const raw = await analyzeWithLlm(
      client,
      ctx.orgSettings.llmModel,
      IAC_STACK_PROMPT,
      userContent,
      { maxTokens: maxResponseTokens },
    );
    const parsed = parseLlmJsonResponse<{ findings: IacLlmFinding[] }>(raw, {
      findings: [],
    });

    return (parsed.findings || [])
      .filter(
        (f) =>
          f.title &&
          f.severity &&
          f.filePath &&
          (f.confidence ?? 0) >= IAC_MIN_CONFIDENCE_DEFAULT,
      )
      .map((f) => {
        const lines = lineMaps.get(f.filePath) || [];
        const base: RawFinding = {
          scanner: "IAC",
          severity: normalizeSeverity(f.severity),
          title: f.title,
          description: f.description,
          filePath: f.filePath,
          startLine: f.startLine,
          endLine: f.endLine,
          snippet: buildSnippet(lines, f.startLine, f.endLine),
          cweId: f.cweId,
          confidence: f.confidence ?? IAC_MIN_CONFIDENCE_DEFAULT,
          ruleId: `IAC-${f.cweId || "STACK"}`,
          metadata: {
            ...(f.metadata || {}),
            stackId: stack.id,
            remediation:
              f.recommendation ||
              (typeof f.metadata?.remediation === "string"
                ? f.metadata.remediation
                : undefined),
            category: "IaC",
          },
        };
        return enrichFinding(base, base.metadata as Record<string, unknown>, {
          whatIsWrong: f.title,
          where: `${f.filePath}:${f.startLine}`,
          whyExploitable:
            (f.metadata?.attackPath as string) || f.description,
          attackPath: f.metadata?.attackPath as string,
          impact: (f.metadata?.exposedAsset as string) || f.description,
          fix:
            (f.metadata?.remediation as string) ||
            f.recommendation ||
            "Apply IaC fix per recommendation.",
          validation: (
            f.metadata?.validationSteps as string[] | undefined
          )?.join("; "),
        });
      });
  } catch (err) {
    logger.error({ err, stack: stack.id }, "IaC stack analysis failed");
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

function buildSnippet(
  lines: string[],
  startLine?: number,
  endLine?: number,
): string | undefined {
  if (!startLine || startLine < 1 || lines.length === 0) return undefined;
  const start = Math.max(0, startLine - 3);
  const end = Math.min(lines.length, (endLine || startLine) + 2);
  return lines
    .slice(start, end)
    .map((line, index) => `${start + index + 1}: ${line}`)
    .join("\n");
}
