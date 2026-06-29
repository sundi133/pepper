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
import { applySeverityCalibration } from "@/lib/severity-calibration";
import {
  SKIP_DIRECTORIES,
  LLM_MAX_FILE_SIZE_BYTES,
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
  MAX_LLM_CONCURRENCY,
  IAC_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";
import { logger } from "@/lib/logger";

const IAC_STACK_PROMPT = `You are an expert IaC security auditor performing STACK-LEVEL analysis.
Analyze ALL files in the stack together (Dockerfile+compose, Terraform module+vars, K8s+Helm, CI+deploy configs).
Do NOT report hardcoded secrets — those belong to the secrets scanner.
For each finding include: exact misconfiguration, exposed asset, attack path, environment if visible, concrete fix, validation step.
Confidence >= 0.80 only.

COVERAGE MATRIX — check every stack for:

**DOCKER & CONTAINER:**
- Running as root (USER not set or USER root), privileged:true, allowPrivilegeEscalation:true
- host network/pid/ipc mode, docker.sock mounted, dangerous capabilities (SYS_ADMIN, NET_ADMIN, ALL)
- :latest tags without digest pin, no HEALTHCHECK, writable root filesystem (readOnlyRootFilesystem missing)
- Secrets in ENV or ARG (use --build-secret or runtime inject instead), COPY of .env or credential files into image
- Sensitive files copied into image that should be .dockerignore'd

**TERRAFORM / CLOUD IaC:**
- Public S3 buckets (acl=public-read/write, block_public_acls=false), missing bucket versioning or encryption
- Overly permissive IAM (Action:* or Resource:* or Principal:*), allow all ingress from 0.0.0.0/0 on non-80/443 ports
- Unencrypted RDS/DynamoDB/EBS/S3, missing deletion_protection, missing backup retention
- Hardcoded provider credentials (aws_access_key/secret_key inline), missing required_providers version pin
- Unsafe remote state without encryption or state lock

**KUBERNETES:**
- Missing resources.limits (CPU/mem), missing NetworkPolicy (allow all pod-to-pod traffic)
- ServiceAccount with automountServiceAccountToken:true when not needed, default service account used
- Overly permissive RBAC: ClusterRoleBinding to default SA, verbs:["*"] or resources:["*"]
- hostPath volumes, secrets stored in ConfigMap instead of Secret resource
- Missing securityContext.runAsNonRoot, missing securityContext.readOnlyRootFilesystem

**CI/CD (GitHub Actions, GitLab CI):**
- pull_request_target workflow with code checkout from fork (allows fork code to run with secrets access)
- Unpinned action references (uses: owner/action@v4 instead of pinned SHA)
- GITHUB_TOKEN with write permissions broader than needed
- Secrets exposed via echo, run: env, or set-output without masking
- Self-hosted runner on public repository (allows RCE from untrusted fork PRs)

**HELM:**
- Hard-coded credentials in values.yaml, missing .helmignore for secret files
- Permissive ingress without TLS, missing pod security context in chart templates

Return JSON:
{
  "findings": [{
    "title": "string", "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "description": "string", "filePath": "string",
    "startLine": <int>, "endLine": <int>,
    "cweId": "CWE-XXX", "confidence": <0.80-1.0>,
    "recommendation": "string",
    "metadata": { "exposedAsset": "string", "attackPath": "string", "environment": "string", "validationSteps": ["string"], "remediation": "string" }
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

    // Count total lines in all IaC files
    let totalIacLoc = 0;
    for (const stack of stacks) {
      for (const { filePath } of stack.files) {
        try {
          const content = fs.readFileSync(path.join(ctx.workDir, filePath), "utf-8");
          totalIacLoc += content.split("\n").length;
        } catch {
          // ignore read errors
        }
      }
    }

    ctx.onProgress?.(`IaC: analyzing ${stacks.length} configuration stack(s) (${totalIacLoc} LOC)...`);

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
      const content = fs.readFileSync(fullPath, "utf-8");
      if (!content.trim()) continue;
      if (Buffer.byteLength(content, "utf8") > LLM_MAX_FILE_SIZE_BYTES) continue;
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
          (f.confidence ?? 0) >= IAC_MIN_CONFIDENCE_DEFAULT &&
          !isInlineSuppressed(lineMaps.get(f.filePath) || [], f.startLine),
      )
      .map((f) => {
        const lines = lineMaps.get(f.filePath) || [];
        const raw: RawFinding = {
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
        const base = applySeverityCalibration(raw);
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

/**
 * Check whether the source lines around a finding contain a `pepper:ignore`
 * suppression comment.  Supports common IaC comment styles:
 *   # pepper:ignore          (YAML, HCL, Dockerfile, Python)
 *   // pepper:ignore         (HCL/Jsonnet)
 *   /* pepper:ignore *​/      (JSON-with-comments)
 *
 * We check the finding line itself and the line immediately above it (the
 * standard placement for inline suppression comments).
 */
const PEPPER_IGNORE = /pepper:ignore/i;

function isInlineSuppressed(
  lines: string[],
  startLine?: number,
): boolean {
  if (!startLine || startLine < 1 || lines.length === 0) return false;
  const idx = startLine - 1; // 0-based
  if (idx < lines.length && PEPPER_IGNORE.test(lines[idx])) return true;
  if (idx > 0 && PEPPER_IGNORE.test(lines[idx - 1])) return true;
  return false;
}
