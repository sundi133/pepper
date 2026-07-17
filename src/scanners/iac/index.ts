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

IMPORTANT: Filter strictly for ACTIONABLE findings only. Avoid:
- Generic best practices without concrete security impact (e.g., missing HEALTHCHECK, missing NetworkPolicy in dev clusters)
- Findings about missing optional features unrelated to security boundaries
- Issues that only matter in production if this is clearly a development/example stack
- Speculative or low-probability attack paths
Only report if: (1) explicit misconfiguration exists, (2) real exploitability is demonstrated, (3) impact is concrete & severe.

For each REAL finding include: exact misconfiguration, exposed asset, direct attack path, concrete fix.
Minimum confidence: 0.85. Only report findings you are confident about.

CRITICAL-ONLY PATTERNS (only report if you are 100% certain):
- Running as root in production containers (explicit USER root or no USER directive in multi-stage without root dropping)
- Explicit network exposure of sensitive services (e.g., database port 3306 open to 0.0.0.0/0)
- Hard-coded credentials visible in code (AWS keys, database passwords in plaintext)
- Publicly writable cloud storage (S3 with public-read/write ACL explicitly set)

HIGH-SEVERITY PATTERNS (report if clear evidence):
- Dangerous capabilities (SYS_ADMIN, NET_ADMIN, SYS_RAWIO) in containers
- Privilege escalation enabled (privileged:true, allowPrivilegeEscalation:true, no_new_privs missing)
- IAM overpermissions (Action:"*" or Resource:"*" or Principal:"*" without condition)
- Unencrypted sensitive storage (RDS/DynamoDB without encryption, KMS disabled)
- Missing secret encryption (Kubernetes secrets stored in etcd unencrypted due to explicit misconfiguration)
- Dangerous RBAC (ClusterRoleBinding to default ServiceAccount with high-risk verbs)
- pull_request_target workflows checking out untrusted fork code with secrets access

MEDIUM-SEVERITY PATTERNS (report if explicit misconfiguration):
- host network/pid/ipc mode usage
- docker.sock mounted into containers
- Secrets passed via ENV/ARG instead of secrets management
- :latest image tags without digest pins in production contexts
- Missing resource limits in Kubernetes (only if this causes denial-of-service vectors)
- Overly permissive ingress rules (0.0.0.0/0 on non-standard ports)
- Unpinned action versions in CI/CD (only if the action has known vulnerabilities)
- Missing deletion protection on critical resources

LOW-SEVERITY PATTERNS (report only if part of a larger attack chain):
- readOnlyRootFilesystem missing (only if combined with writable mount points or secrets)
- runAsNonRoot missing (only if combined with writable files or privilege escalation paths)
- Missing pod security policies (only if misconfigurations allow privilege escalation)

Return JSON:
{
  "findings": [{
    "title": "string", "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "description": "string (explain the exact misconfiguration and why it matters)", "filePath": "string",
    "startLine": <int>, "endLine": <int>,
    "cweId": "CWE-XXX", "confidence": <0.85-1.0>,
    "recommendation": "string (specific, actionable fix)",
    "metadata": { "exposedAsset": "string", "attackPath": "string (concrete attack vector)", "validationSteps": ["string"], "remediation": "string" }
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
