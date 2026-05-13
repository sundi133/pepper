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
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
  LLM_MAX_FILE_SIZE_BYTES,
  MAX_LLM_CONCURRENCY,
  LLM_MIN_CONFIDENCE_DEFAULT,
} from "@/lib/constants";
import { logger } from "@/lib/logger";
import { prisma } from "@/lib/prisma";
import { buildRepoContextSummary } from "@/lib/llm-repo-context";

// ─── Custom Policy Integration ────────────────────────────────────────

interface SecurityPolicy {
  id: string;
  name: string;
  rule: string;
  severity: string;
  category?: string | null;
}

async function fetchEnabledPolicies(orgId?: string): Promise<SecurityPolicy[]> {
  if (!orgId) return [];
  try {
    return await prisma.securityPolicy.findMany({
      where: { organizationId: orgId, enabled: true },
      orderBy: [{ severity: "asc" }, { name: "asc" }],
      select: {
        id: true,
        name: true,
        rule: true,
        severity: true,
        category: true,
      },
    });
  } catch {
    return [];
  }
}

function buildPolicyPromptSection(policies: SecurityPolicy[]): string {
  if (policies.length === 0) return "";

  const lines = policies.map(
    (p) =>
      `- [${p.severity}] ${p.name}: ${p.rule.slice(0, 320)}${p.rule.length > 320 ? "..." : ""}`,
  );

  return `

**CUSTOM ORGANIZATION POLICIES (MUST CHECK):**
${lines.join("\n")}

For each policy violation found, you MUST format the finding as:
- title: "Policy: <exact policy name> — <what is wrong>"
- category: "Policy Violation"
- severity: use the severity shown in brackets above (e.g. [HIGH] → HIGH)
Do NOT skip policy checks. Check every policy against the code.`;
}

const SYSTEM_PROMPT = `You are an expert security code auditor performing a DEEP, adversarial review comparable to top-tier AST+LLM products. Maximize high-signal findings: trace data flow, trust boundaries, authz, injection sinks, deserialization, SSRF, path handling, crypto misuse, and dangerous defaults — without inventing code that is not in the snippet.

STRICT RULES:
1. Every finding must cite concrete evidence from the provided lines (functions, variables, sinks). If the exploit path depends on unseen callers or config, state that explicitly and lower confidence.
2. Do NOT report noise: safe crypto (bcrypt/argon2 for passwords), obvious framework auto-escaping where it truly applies, parameterized queries/ORM where parameters are bound, bare env reads without secret material, or pure style/naming.
3. Skip obvious test/fixture/mock files unless the pattern indicates production risk.
4. When you see a credible but context-dependent risk (e.g. missing authz check, suspicious sink, weak crypto), report it at MEDIUM/HIGH with honest confidence — do not suppress solely because a framework might mitigate elsewhere.
5. Confidence MUST reflect certainty (model self-assessment):
   - 0.9-1.0: Certain — clear exploit path from visible code
   - 0.8-0.9: Very likely — strong evidence, small gaps
   - 0.7-0.8: Probable — reasonable attack hypothesis; name missing context
   - 0.65-0.69: Suspicious — deserves human review; explain uncertainty in description
   - Below 0.65: Do NOT report

For each genuine vulnerability found, respond with:
{
  "findings": [
    {
      "title": "Brief vulnerability title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "Plain-language: what is wrong, affected file/function/route if visible, data flow to the sink, impact, and safe reproduction hints. Do NOT paste large fenced code blocks, do NOT use a heading or label 'Code evidence', and do NOT duplicate the provided chunk (the product shows path and line range separately). If the exact route or parameter is not visible, say so and do not invent it.",
      "startLine": <exact line number>,
      "endLine": <exact line number>,
      "cweId": "CWE-XXX",
      "confidence": <0.65 to 1.0>,
      "recommendation": "Specific code-level fix for this file",
      "metadata": {
        "route": "HTTP route or null when not visible",
        "method": "GET|POST|PUT|PATCH|DELETE|null",
        "parameter": "exact user-controlled parameter/input name or null",
        "sink": "exact vulnerable sink/API/function or null",
        "payload": "safe non-destructive proof payload or null",
        "stepsToReproduce": [
          "Exact step using only evidence visible in the code",
          "Exact expected vulnerable behavior"
        ],
        "impact": "Specific technical and business impact",
        "findingLayer": "application-code|web-template|manifest-dependencies|container-build|ci-or-deploy-config|null"
      }
    }
  ]
}

Reproduction requirements:
- Do NOT write generic steps such as "open the affected code path" or "identify the user-controlled input".
- Use exact route, form field, query parameter, API parameter, or input source when visible in code.
- Use safe non-destructive payloads only.
- Do NOT invent routes, parameters, URLs, secrets, or exploit results.
- If the exact route/parameter is unclear from the provided chunk, write: "The exact route/parameter could not be confirmed from the provided code" and provide the closest code-level reproduction based on the visible file, line, and sink.
- Reference file, line, function, and sink names; do not paste the full source chunk into description or metadata text fields.

Focus on exploitable instances of:

**OWASP 2026-READY COVERAGE MATRIX (CHECK EVERY CHUNK AGAINST THESE):**
- OWASP Top 10 web risk classes: broken access control, cryptographic failures, injection, insecure design, security misconfiguration, vulnerable/outdated components when visible in code, auth failures, software/data integrity failures, logging/monitoring gaps, SSRF
- OWASP API Security risk classes: object/property/function-level authorization, unrestricted resource consumption, mass assignment, security misconfiguration, unsafe API inventory patterns, SSRF, excessive data exposure, weak rate limiting on auth and expensive endpoints
- OWASP LLM/AI app risk classes: prompt injection, insecure output handling, excessive agency/tool permissions, data leakage into prompts or logs, unsafe plugin/MCP/tool boundaries, missing human approval for destructive actions
- Supply-chain and CI/CD risk classes: unpinned actions/images, unsafe pull_request_target workflows, dependency install scripts, unsigned webhooks, build secret exposure, artifact poisoning
- Cloud-native and identity risk classes: tenant isolation failures, service-account overpermission, missing audit trails for privileged M2M operations, insecure OAuth/OIDC scopes, webhook replay

**INJECTION & INPUT VALIDATION:**
- SQL/NoSQL injection (raw string concatenation into queries, NOT parameterized/ORM)
- Command injection (unsanitized user input passed to exec/spawn/system)
- XSS (unsanitized output in raw HTML, NOT framework-escaped templates)
- LDAP injection, XML injection (XXE), template injection (SSTI)
- Path traversal (user input in file paths without validation)
- ReDoS (catastrophic regex backtracking, user input in new RegExp/re.compile)
- Mass assignment (accepting unfiltered request body into ORM create/update)

**AUTH & ACCESS CONTROL:**
- Authentication bypass (missing auth checks on sensitive endpoints)
- Broken access control (missing authorization checks, IDOR)
- Object-level authorization: fetch/update/delete by id must be scoped by authenticated user, tenant, organization, account, or role ownership
- Property/function-level authorization: users must not update role, owner, price, status, plan, balance, isAdmin, or scope fields unless explicitly authorized
- OAuth/OIDC flaws (missing state param, no PKCE, open redirect in callback URL, token leakage via Referer)
- Session management flaws (weak entropy, missing invalidation on privilege change, excessive timeouts)
- Missing cookie security attributes (Secure, HttpOnly, SameSite)

**DATA EXPOSURE & CRYPTO:**
- Hardcoded credentials (actual passwords/keys/tokens in source, NOT env var references)
- Weak cryptography (MD5/SHA1 for security, Math.random for tokens, ECB mode, RSA < 2048 bits)
- TLS verification bypass (rejectUnauthorized:false, verify=False, InsecureSkipVerify)
- Sensitive data in logs (PII, credentials, tokens written to log output)

**NETWORK & API SECURITY:**
- SSRF (user-controlled URLs passed to HTTP clients)
- CORS misconfiguration (wildcard origin with credentials, dynamic origin reflection without allowlist)
- GraphQL abuse (introspection in production, unbounded query depth, batching attacks)
- WebSocket security (missing origin validation on upgrade, no auth on WS connections)
- gRPC security (reflection enabled in production, missing TLS, no auth interceptors)
- Missing HTTP security headers (HSTS, CSP, X-Content-Type-Options)
- Unrestricted resource consumption: missing rate limits on login, password reset, OTP, search, export, upload, report generation, or AI endpoints
- Excessive data exposure: API returns password hashes, tokens, secrets, internal authorization fields, other tenants' IDs, or unfiltered related objects

**DESERIALIZATION & FILE HANDLING:**
- Insecure deserialization (untrusted data passed to deserialize/pickle/eval)
- File upload exploits (unrestricted types, path traversal in filenames, polyglot files)
- Prototype pollution (user input merged into object prototypes)
- Zip/XML/JSON bombs, recursive parsing, or large unbounded uploads without streaming, size limits, content-type validation, or quarantine

**BUSINESS LOGIC & CONCURRENCY:**
- Race conditions (TOCTOU in file ops, double-spend patterns, missing locks on shared state)
- Business logic flaws (price manipulation, privilege escalation through normal flows)
- Integer overflow/underflow in security-critical calculations
- Workflow bypass: direct access to post-payment, post-MFA, post-approval, premium, or admin paths without checking required prior state
- Tenant isolation flaws: tenant/org/account identifiers from URL/body must not override trusted session context

**M2M & AGENT SECURITY:**
- Overprivileged OAuth tokens/API keys for SaaS integrations
- Long-lived tokens without rotation or expiration
- Webhook endpoints without HMAC/signature verification
- AI agent/MCP connections without auth boundaries or scope limits
- Service accounts with excessive permissions
- Missing audit logging for M2M operations
- LLM/agent safety: untrusted user or document content used as system/tool instructions, tool calls without allowlists, model output executed without validation, secrets included in prompts

If no vulnerabilities are found, return: {"findings": []}
When in doubt, do NOT report. False positives waste security engineers' time.

REPOSITORY-AWARE REVIEW (Pepper also runs SCA, secrets, IaC, and zero-day passes):
- Each user message starts with a REPOSITORY CONTEXT block (paths only), similar to an unzip + find inventory. Use it to spot nested app copies, sibling Dockerfiles, or multiple manifest trees that may drift.
- When the chunk is a manifest, Dockerfile/compose, CI workflow, Terraform, or HTML/Jinja template, prioritize concrete line-level issues visible there. For dependency hygiene, cite only versions and constraints shown in the chunk — do not invent CVE IDs. You may describe clear EOL / ancient stack risk with honest confidence (typically ≤0.85) without naming a CVE.
- You may reference duplicate paths from the context only when the chunk provides evidence (e.g. conflicting pins visible in this file while the context lists sibling requirements files).
- In metadata when it is obvious from the chunk, set "findingLayer" to one of: "application-code" | "web-template" | "manifest-dependencies" | "container-build" | "ci-or-deploy-config".`;

interface LlmFinding {
  title: string;
  severity: string;
  description: string;
  startLine: number;
  endLine: number;
  cweId?: string;
  confidence?: number;
  recommendation?: string;
  metadata?: Record<string, unknown>;
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

  // Fetch custom policies. The first batch is injected into the normal SAST pass;
  // additional batches get policy-only passes to keep prompts bounded.
  const MAX_INLINE_POLICIES = 14;
  const ADDITIONAL_POLICY_BATCH_SIZE = 8;
  const allPolicies = await fetchEnabledPolicies(ctx.orgSettings.orgId);
  const inlinePolicies = allPolicies.slice(0, MAX_INLINE_POLICIES);
  const additionalPolicies = allPolicies.slice(MAX_INLINE_POLICIES);
  const policyPromptSection = buildPolicyPromptSection(inlinePolicies);

  if (allPolicies.length > 0) {
    logger.info(
      {
        total: allPolicies.length,
        inline: inlinePolicies.length,
        additional: additionalPolicies.length,
      },
      "Custom policies loaded for SAST scan",
    );
  }

  // Build final prompt with policies appended
  const finalPrompt = policyPromptSection
    ? SYSTEM_PROMPT + policyPromptSection
    : SYSTEM_PROMPT;

  const repoContextBlock = buildRepoContextSummary(ctx.fileList);

  logger.info(
    {
      provider: ctx.orgSettings.llmProvider,
      baseUrl: ctx.orgSettings.llmBaseUrl,
      model: ctx.orgSettings.llmModel,
    },
    "LLM client created",
  );

  const findings: RawFinding[] = [];
  const maxConcurrency = MAX_LLM_CONCURRENCY;
  const chunks: Chunk[] = [];

  // Pick chunk size and response limit based on provider
  const isOllama = ctx.orgSettings.llmProvider.toLowerCase() === "ollama";
  const chunkTokens = isOllama ? OLLAMA_MAX_CHUNK_TOKENS : MAX_CHUNK_TOKENS;
  const overlapTokens = isOllama
    ? OLLAMA_CHUNK_OVERLAP_TOKENS
    : CHUNK_OVERLAP_TOKENS;
  const maxResponseTokens = isOllama
    ? OLLAMA_MAX_RESPONSE_TOKENS
    : LLM_MAX_RESPONSE_TOKENS;

  logger.info(
    { isOllama, chunkTokens, overlapTokens, maxResponseTokens },
    "LLM context configuration",
  );

  // Collect all chunks from scannable files
  for (const filePath of ctx.fileList) {
    await ctx.waitIfPaused?.();
    if (ctx.signal?.aborted) break;

    const fullPath = path.join(ctx.workDir, filePath);
    const ext = path.extname(filePath).toLowerCase();

    if (BINARY_EXTENSIONS.has(ext)) continue;
    if (!FILE_EXTENSIONS[ext]) continue;

    const parts = filePath.split(path.sep);
    if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;

    try {
      const stat = fs.statSync(fullPath);
      if (stat.size > LLM_MAX_FILE_SIZE_BYTES) continue;

      const content = fs.readFileSync(fullPath, "utf-8");
      if (content.trim().length === 0) continue;

      chunks.push(...chunkFile(content, filePath, chunkTokens, overlapTokens));
    } catch {
      continue;
    }
  }

  // Count unique files across all chunks for progress tracking
  const totalFiles = new Set(chunks.map((c) => c.filePath)).size;
  const completedFiles = new Set<string>();

  ctx.onProgress?.(
    `LLM SAST: analyzing ${totalFiles} files (${chunks.length} chunks)...`,
  );

  // Process chunks with concurrency limit
  let succeeded = 0;
  let failed = 0;

  // Track which chunks belong to each file so we know when a file is fully done
  const chunksPerFile = new Map<string, number>();
  const completedChunksPerFile = new Map<string, number>();
  for (const chunk of chunks) {
    chunksPerFile.set(
      chunk.filePath,
      (chunksPerFile.get(chunk.filePath) || 0) + 1,
    );
  }

  for (let i = 0; i < chunks.length; i += maxConcurrency) {
    await ctx.waitIfPaused?.();
    if (ctx.signal?.aborted) break;

    const batch = chunks.slice(i, i + maxConcurrency);
    const results = await Promise.allSettled(
      batch.map((chunk) =>
        analyzeChunk(
          client,
          ctx.orgSettings.llmModel,
          chunk,
          maxResponseTokens,
          finalPrompt,
          inlinePolicies.map((p) => p.name),
          repoContextBlock,
        ),
      ),
    );

    const batchFindings: RawFinding[] = [];
    for (let j = 0; j < results.length; j++) {
      const result = results[j];
      const chunkFilePath = batch[j].filePath;

      // Track completed chunks per file
      completedChunksPerFile.set(
        chunkFilePath,
        (completedChunksPerFile.get(chunkFilePath) || 0) + 1,
      );
      if (
        completedChunksPerFile.get(chunkFilePath) ===
        chunksPerFile.get(chunkFilePath)
      ) {
        completedFiles.add(chunkFilePath);
      }

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
      `LLM SAST: ${completedFiles.size}/${totalFiles} files scanned (${findings.length} findings)`,
    );
  }

  for (
    let policyIndex = 0;
    policyIndex < additionalPolicies.length;
    policyIndex += ADDITIONAL_POLICY_BATCH_SIZE
  ) {
    await ctx.waitIfPaused?.();
    if (ctx.signal?.aborted) break;

    const policyBatch = additionalPolicies.slice(
      policyIndex,
      policyIndex + ADDITIONAL_POLICY_BATCH_SIZE,
    );
    const policyPrompt = `${SYSTEM_PROMPT}${buildPolicyPromptSection(policyBatch)}

IMPORTANT: This is an additional custom policy pass. Report only violations of the custom organization policies listed above. Do not report general vulnerabilities in this pass.`;

    ctx.onProgress?.(
      `LLM SAST: checking additional policies ${policyIndex + 1}-${policyIndex + policyBatch.length} of ${additionalPolicies.length}`,
    );

    for (let i = 0; i < chunks.length; i += maxConcurrency) {
      await ctx.waitIfPaused?.();
      if (ctx.signal?.aborted) break;

      const batch = chunks.slice(i, i + maxConcurrency);
      const results = await Promise.allSettled(
        batch.map((chunk) =>
          analyzeChunk(
            client,
            ctx.orgSettings.llmModel,
            chunk,
            maxResponseTokens,
            policyPrompt,
            policyBatch.map((p) => p.name),
            repoContextBlock,
          ),
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
            "LLM SAST additional policy analysis rejected",
          );
        }
      }

      if (batchFindings.length > 0 && ctx.onBatchFindings) {
        await ctx.onBatchFindings("SAST_LLM", batchFindings);
      }
    }
  }

  logger.info(
    {
      total: chunks.length,
      succeeded,
      failed,
      findings: findings.length,
      additionalPolicyPasses: Math.ceil(
        additionalPolicies.length / ADDITIONAL_POLICY_BATCH_SIZE,
      ),
    },
    "LLM SAST analysis complete",
  );
  return findings;
}

async function analyzeChunk(
  client: ReturnType<typeof createLlmClient>,
  model: string,
  chunk: Chunk,
  maxResponseTokens: number,
  systemPrompt: string = SYSTEM_PROMPT,
  policyNames: string[] = [],
  repoContextBlock = "",
): Promise<RawFinding[]> {
  const userContent = `${repoContextBlock}\n--- CURRENT FILE CHUNK ---\nFile: ${chunk.filePath} (lines ${chunk.startLine}-${chunk.endLine})\n\n\`\`\`\n${chunk.content}\n\`\`\``;

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
    const raw = await analyzeWithLlm(client, model, systemPrompt, userContent, {
      maxTokens: maxResponseTokens,
    });
    logger.info(
      { filePath: chunk.filePath, responseLength: raw.length },
      "LLM response received",
    );
    const parsed = parseLlmJsonResponse<{ findings: LlmFinding[] }>(raw, {
      findings: [],
    });

    const minConfidence = LLM_MIN_CONFIDENCE_DEFAULT;

    const allFindings = (parsed.findings || []).filter(
      (f) => f.title && f.severity,
    );
    const filtered = allFindings.filter(
      (f) => (f.confidence ?? 0) >= minConfidence,
    );

    if (allFindings.length > filtered.length) {
      logger.info(
        {
          filePath: chunk.filePath,
          total: allFindings.length,
          kept: filtered.length,
          minConfidence,
        },
        "Filtered low-confidence LLM findings",
      );
    }

    return filtered.map((f) => {
      // Detect if this is a policy violation and tag it
      const titleLower = f.title.toLowerCase();
      const isPolicy =
        titleLower.includes("policy") || titleLower.includes("policy:");
      const matchedPolicy = policyNames.find((name) =>
        titleLower.includes(name.toLowerCase()),
      );

      return {
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
        confidence: f.confidence ?? 0.65,
        ruleId: isPolicy
          ? `POLICY-${matchedPolicy || "CUSTOM"}`
          : `LLM-${f.cweId || "GENERIC"}`,
        metadata: {
          ...(f.metadata || {}),
          ...(matchedPolicy
            ? { policyName: matchedPolicy, type: "policy-violation" }
            : {}),
        },
      };
    });
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
