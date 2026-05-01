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
} from "@/lib/constants";
import { logger } from "@/lib/logger";
import { prisma } from "@/lib/prisma";

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
      `- [${p.severity}] ${p.name}: ${p.rule.slice(0, 200)}${p.rule.length > 200 ? "..." : ""}`,
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

const SYSTEM_PROMPT = `You are an expert security code auditor performing a strict vulnerability review. Your goal is PRECISION over recall — report ONLY vulnerabilities you are highly confident are real and exploitable.

STRICT RULES:
1. Only report a finding if you can explain a concrete attack scenario — how an attacker would exploit it.
2. Do NOT report theoretical or speculative issues. If the code has proper input validation, sanitization, or framework-level protections, it is NOT vulnerable.
3. Do NOT flag:
   - Safe uses of crypto (e.g. bcrypt, argon2, scrypt for password hashing)
   - Framework-provided CSRF/XSS protections (e.g. React JSX auto-escaping, Django templates, Rails ERB)
   - Parameterized queries or ORM-generated queries (these are NOT SQL injection)
   - Environment variable reads or config files (these are NOT hardcoded secrets unless a real key/password literal is present)
   - Test files, fixtures, or mock data
   - Informational or best-practice suggestions — only report actual vulnerabilities
4. Confidence MUST reflect how certain you are that this is a real, exploitable vulnerability:
   - 0.9-1.0: Certain — clear, unambiguous vulnerability with direct exploit path
   - 0.8-0.9: Very likely — strong evidence, minor ambiguity about context
   - 0.7-0.8: Probable — likely vulnerable but depends on runtime context
   - Below 0.7: Do NOT report it

For each genuine vulnerability found, respond with:
{
  "findings": [
    {
      "title": "Brief vulnerability title",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "What the vulnerability is, how it can be exploited, and what the impact is",
      "startLine": <exact line number>,
      "endLine": <exact line number>,
      "cweId": "CWE-XXX",
      "confidence": <0.7 to 1.0>,
      "recommendation": "Specific fix for this code"
    }
  ]
}

Focus on exploitable instances of:

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

**DESERIALIZATION & FILE HANDLING:**
- Insecure deserialization (untrusted data passed to deserialize/pickle/eval)
- File upload exploits (unrestricted types, path traversal in filenames, polyglot files)
- Prototype pollution (user input merged into object prototypes)

**BUSINESS LOGIC & CONCURRENCY:**
- Race conditions (TOCTOU in file ops, double-spend patterns, missing locks on shared state)
- Business logic flaws (price manipulation, privilege escalation through normal flows)
- Integer overflow/underflow in security-critical calculations

**M2M & AGENT SECURITY:**
- Overprivileged OAuth tokens/API keys for SaaS integrations
- Long-lived tokens without rotation or expiration
- Webhook endpoints without HMAC/signature verification
- AI agent/MCP connections without auth boundaries or scope limits
- Service accounts with excessive permissions
- Missing audit logging for M2M operations

If no vulnerabilities are found, return: {"findings": []}
When in doubt, do NOT report. False positives waste security engineers' time.`;

interface LlmFinding {
  title: string;
  severity: string;
  description: string;
  startLine: number;
  endLine: number;
  cweId?: string;
  confidence?: number;
  recommendation?: string;
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

  // Fetch custom policies (inject into prompt — zero extra LLM calls for first 10)
  const MAX_INLINE_POLICIES = 10;
  const allPolicies = await fetchEnabledPolicies(ctx.orgSettings.orgId);
  const inlinePolicies = allPolicies.slice(0, MAX_INLINE_POLICIES);
  const policyPromptSection = buildPolicyPromptSection(inlinePolicies);

  if (allPolicies.length > 0) {
    logger.info(
      { total: allPolicies.length, inline: inlinePolicies.length },
      "Custom policies loaded for SAST scan",
    );
  }
  if (allPolicies.length > MAX_INLINE_POLICIES) {
    logger.warn(
      { total: allPolicies.length, max: MAX_INLINE_POLICIES },
      `Only first ${MAX_INLINE_POLICIES} policies injected into prompt. Remaining ${allPolicies.length - MAX_INLINE_POLICIES} will not be checked. Consider consolidating policies.`,
    );
  }

  // Build final prompt with policies appended
  const finalPrompt = policyPromptSection
    ? SYSTEM_PROMPT + policyPromptSection
    : SYSTEM_PROMPT;

  logger.info(
    {
      provider: ctx.orgSettings.llmProvider,
      baseUrl: ctx.orgSettings.llmBaseUrl,
      model: ctx.orgSettings.llmModel,
    },
    "LLM client created",
  );

  const findings: RawFinding[] = [];
  const maxConcurrency = parseInt(process.env.MAX_LLM_CONCURRENCY || "2");
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
    if (ctx.signal?.aborted) break;

    const fullPath = path.join(ctx.workDir, filePath);
    const ext = path.extname(filePath).toLowerCase();

    if (BINARY_EXTENSIONS.has(ext)) continue;
    if (!FILE_EXTENSIONS[ext]) continue;

    const parts = filePath.split(path.sep);
    if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;

    try {
      const content = fs.readFileSync(fullPath, "utf-8");
      if (content.trim().length === 0) continue;

      // Every file gets chunked into LLM-friendly pieces, no size limit
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
  const totalBatches = Math.ceil(chunks.length / maxConcurrency);

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
    if (ctx.signal?.aborted) break;

    const batchNum = Math.floor(i / maxConcurrency) + 1;
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

  logger.info(
    { total: chunks.length, succeeded, failed, findings: findings.length },
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
): Promise<RawFinding[]> {
  const userContent = `File: ${chunk.filePath} (lines ${chunk.startLine}-${chunk.endLine})\n\n\`\`\`\n${chunk.content}\n\`\`\``;

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

    const minConfidence = parseFloat(process.env.LLM_MIN_CONFIDENCE || "0.7");

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
        confidence: f.confidence ?? 0.7,
        ruleId: isPolicy
          ? `POLICY-${matchedPolicy || "CUSTOM"}`
          : `LLM-${f.cweId || "GENERIC"}`,
        metadata: matchedPolicy
          ? { policyName: matchedPolicy, type: "policy-violation" }
          : undefined,
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
