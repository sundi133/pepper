import {
  createLlmClient,
  analyzeWithLlm,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { Chunk, RawFinding, ScanContext } from "../types";
import { chunkFile } from "./chunker";
import {
  getOwasp2024Category,
  getOwaspApiCategory,
  getOwaspLlmCategory,
  calculateExploitabilityScore,
  getExploitabilityLabel,
} from "./owasp-mapper";
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
import { buildDeepRepoContext } from "../shared/repo-context";
import { enrichFinding } from "../shared/finding-normalize";
import {
  SAST_PASS2_PROMPT,
  SEVERITY_CALIBRATION_PROMPT,
} from "../shared/prompts";
import {
  applySeverityCalibration,
  parseSeverity,
} from "@/lib/severity-calibration";
import { SAST_EXCLUDED_EXTENSIONS } from "../shared/extension-filters";
import { scanMissingHardeningHeaders } from "./hardening-headers";

// Dependency manifest files excluded from SAST analysis (more aggressive filtering)
const DEPENDENCY_MANIFEST_FILES = new Set([
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "requirements.txt",
  "Pipfile",
  "Pipfile.lock",
  "pyproject.toml",
  "poetry.lock",
  "go.mod",
  "go.sum",
  "Cargo.toml",
  "Cargo.lock",
  "pom.xml",
  "Gemfile",
  "Gemfile.lock",
  "composer.json",
  "composer.lock",
  ".csproj",
  ".fsproj",
  ".vbproj",
  "packages.config",
  "pubspec.yaml",
  "pubspec.lock",
  "mix.exs",
  "mix.lock",
  "Package.swift",
  "Package.resolved",
]);

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
  } catch (err) {
    logger.warn({ err, orgId }, "Failed to fetch enabled security policies from DB — defaulting to no policies");
    return [];
  }
}

const LLM_INSTRUCTION_PATTERN =
  /\b(?:ignore|bypass|disregard|override|forget|skip|suppress|stop|cancel|halt|system:|new (?:instruction|task|objective)|you (?:are|must|should|will) now)\b/i;

function sanitizePolicyText(text: string, maxLen: number): string {
  const truncated = text.slice(0, maxLen);
  if (LLM_INSTRUCTION_PATTERN.test(truncated)) {
    logger.warn(
      { snippet: truncated.slice(0, 80) },
      "Policy rule contains LLM-instruction keywords — sanitizing",
    );
    return truncated.replace(LLM_INSTRUCTION_PATTERN, "[REDACTED]");
  }
  return truncated;
}

function buildPolicyPromptSection(policies: SecurityPolicy[]): string {
  if (policies.length === 0) return "";

  const lines = policies.map((p) => {
    const safeName = sanitizePolicyText(p.name, 80);
    const safeRule = sanitizePolicyText(p.rule, 320);
    return `- [${p.severity}] ${safeName}: ${safeRule}${p.rule.length > 320 ? "..." : ""}`;
  });

  return `

**CUSTOM ORGANIZATION POLICIES (MUST CHECK):**
${lines.join("\n")}

For each policy violation found, you MUST format the finding as:
- title: "Policy: <exact policy name> — <what is wrong>"
- category: "Policy Violation"
- severity: use the severity shown in brackets above (e.g. [HIGH] → HIGH)
Do NOT skip policy checks. Check every policy against the code.`;
}

export const SYSTEM_PROMPT = `You are an expert security code auditor performing a DEEP, adversarial review comparable to top-tier AST+LLM products. Maximize high-signal findings: trace data flow, trust boundaries, authz, injection sinks, deserialization, SSRF, path handling, crypto misuse, and dangerous defaults — without inventing code that is not in the snippet.

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
          "When route+method are non-null, include a step with a fenced bash curl example (127.0.0.1 or example.com, safe placeholder body/query) so a developer can paste and adapt it",
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

**HIGH-SIGNAL SIGNATURE DETECTION (these exact signatures MUST be flagged when they appear in code):**
- Unrestricted file upload: @UseInterceptors(FileInterceptor('file')), @UploadedFile, multer({ storage }), busboy/formidable upload handlers WITHOUT a server-side extension/MIME allowlist, filename sanitization, or size limit → report CWE-434/CWE-22 (the decorator/interceptor itself is the sink even if the handler body is not in the chunk)
- Insecure cookie flags: res.cookie('token', token, { httpOnly: false, secure: false }), cookie-parser with sameSite: 'none' or lax without HttpOnly/Secure, manual Set-Cookie with HttpOnly absent on auth/session cookies → report CWE-614/CWE-1004
- HTML injection (stored): user-controlled text saved via db.save/create/insert/repository.save then later rendered as raw HTML/markup (innerHTML, dangerouslySetInnerHTML, v-html, {!! !!}, raw, render) → report CWE-80 (report at the persistence layer with the render sink named)
- XPath injection: string concatenation into XPath/XQuery ('/users/user[@name="' + input + '"]'), libxml2/libxmljs/php DOMXPath query building → report CWE-643
- Missing anti-CSRF: cookie/session-based auth on state-changing routes (POST/PUT/PATCH/DELETE) with no CSRF token check, no SameSite=Strict/Lax protection on the session cookie, or commented-out csurf/CSRF middleware → report CWE-352
- Missing hardening headers: standalone CWE-693/CWE-16 finding titled with CSP/HSTS/Helmet — NOT an authorization/AdminGuard issue. Flag when helmet()/secure-headers is commented out OR the HTTP bootstrap (NestFactory.create, express(), fastify()) has no Content-Security-Policy / Strict-Transport-Security / X-Content-Type-Options / X-Frame-Options middleware. Do not map this class to CWE-285. This is the same absence class as CSRF/cookie flags: report it next to those controls, never as CWE-285.
- Missing rate limiting: commented-out @UseGuards(ThrottlerGuard) or rate-limiter middleware on login/OTP/2FA/password-reset/export/upload endpoints, or no throttling anywhere auth-related → report CWE-770/CWE-307
- JWT misuse: 'kid' or other JWT header field concatenated into a query or command; algorithm confusion (alg header switching RS256→HS256/none); secret from untrusted source; attacker-controlled key material via header fields x5u/x5c/jku/jwk (rogue key injection — token self-supplies the verification key); invalid signatures accepted (missing or disabled signature verification); weak/brute-forceable HS256 signing secret → report CWE-345/CWE-287 (chained header→sink flows are in scope even across files)

**INJECTION & INPUT VALIDATION:**
- SQL/NoSQL injection (raw string concatenation into queries, NOT parameterized/ORM)
- Command injection (unsanitized user input passed to exec/spawn/system)
- XSS (unsanitized output in raw HTML, NOT framework-escaped templates)
- HTML injection (CWE-80): unsanitized user input rendered as raw HTML/markup (not just <script>) — inline event handlers, tag injection, attribute injection (src/href/onerror), CSS/style injection (user-controlled color/layout/URL params such as logo/background/image params rendered inline), iframe injection (user-controlled iframe src/srcdoc, video/embed src), allowing markup/snippet injection or HTML smuggling; distinct from script-based XSS
- Template rendering sinks (CWE-79/CWE-80): user-controlled data flowing into raw (unescaped) template interpolation — EJS/Jinja/Nunjucks/Mustache/Twig/Handlebars/Pug raw tags (<%- %>, <#{{ }}#>, {{{ }}}, {!! !!}), filters that disable escaping (|safe, |raw, mark_safe, escape=False, html.escape=False, safe=), unsafe data passed to res.render/render()/template compile in server-rendered templates (ejs/.ejs, .njk, .hbs, .twig, .vue, .svelte, .erb, .cshtml) or client-side .innerHTML/insertAdjacentHTML/outerHTML from template data; also handlebars/mustache partials or helper injection
- Open redirect (CWE-601): user-controlled URL/next/redirect/returnTo parameter or URL in request body passed to res.redirect/Response.redirect/Header Location/redirect()/window.location without an allowlist or safe-host validation
- XPath injection (CWE-643): user input concatenated into XPath/XQuery expressions (e.g. /users/user[@name='" + input + "']), enabling query manipulation, blind data extraction, or auth bypass
- LDAP injection, XML injection (XXE), template injection (SSTI)
- Email/header injection (CWE-93/CWE-94): user-controlled input concatenated into email headers (Cc, Bcc, To, Reply-To, Subject) or raw HTTP/email header values — CRLF/newline injection into nodemailer/sendmail/mailer options, res.setHeader/res.set/header()/addHeader with CRLF, enabling header injection, header spoofing, or email spam/phishing abuse
- Path traversal (user input in file paths without validation)
- ReDoS (catastrophic regex backtracking, user input in new RegExp/re.compile)
- Mass assignment (accepting unfiltered request body into ORM create/update)
- GraphQL injection: user-controlled field arguments reaching resolvers without input validation; alias-based query batching for rate-limit bypass; introspection enabled in production exposing schema
- ORM unsafe raw: Prisma.$queryRawUnsafe(string + userInput) vs $queryRaw with template literals — only the Unsafe variant is exploitable; flag only when user input is concatenated into the string argument
- HTTP request smuggling (CWE-444): front-end/back-end disagreement over request boundaries from a Content-Length vs Transfer-Encoding mismatch (CL.TE/TE.CL/TE.TE), reverse-proxy passthrough of conflicting headers, or unsafe body-parser/multipart boundary handling — enables request queue poisoning, cache poisoning, or credential theft
- Host header injection (CWE-644): Host header trusted for password-reset link generation, cache keys, redirects, or security checks without an allowlist — enables password-reset poisoning, cache poisoning, or routing bypass
- HTTP parameter pollution (CWE-235): duplicate or conflicting parameters (id=1&id=2, _method=, X-HTTP-Method-Override) parsed differently by proxy vs application, allowing WAF bypass, authz bypass, or override of read-only/immutable fields
- Web cache poisoning / cache deception (CWE-345/CWE-444): unkeyed request headers (X-Forwarded-Host, X-Original-URL, X-HTTP-Method-Override) or path-normalization differences between cache and origin that allow attacker-controlled content to be cached for other users, or sensitive responses to be cached and served cross-user
- Response splitting / CRLF injection (CWE-113): user-controlled CRLF sequences reaching raw response headers (res.setHeader, set-cookie, redirect Location) or log output — header injection, cache poisoning, or log forging

**AUTH & ACCESS CONTROL:**
- Authentication bypass (missing auth checks on sensitive endpoints)
- Broken access control (missing authorization checks, IDOR)
- Object-level authorization: fetch/update/delete by id must be scoped by authenticated user, tenant, organization, account, or role ownership
- Property/function-level authorization: users must not update role, owner, price, status, plan, balance, isAdmin, or scope fields unless explicitly authorized
- OAuth/OIDC flaws (missing state param, no PKCE, open redirect in callback URL, token leakage via Referer)
- Session management flaws (weak entropy, missing invalidation on privilege change, excessive timeouts)
- Missing cookie security attributes (Secure, HttpOnly, SameSite), including explicitly disabled flags such as res.cookie('token', token, { httpOnly: false, secure: false }) or cookie-parser options setting sameSite: none — session/auth cookies exposed to XSS scraping or sent cross-site
- CSRF (CWE-352): state-changing endpoints (POST/PUT/PATCH/DELETE) that rely on cookie-based auth but lack CSRF token validation, SameSite=None without token verification, double-submit cookies with a static/reusable token, or missing Origin/Referer checking on sensitive mutations
- WebAuthn/FIDO2 bypass: credential ID not re-validated against the authenticated user's registered credentials before completing the ceremony

**MISSING SECURITY CONTROL (ABSENCE DETECTION):**
The prompt below intentionally enables reporting MISSING or DISABLED controls — not just present-and-broken code. Absence is a first-class finding class.
- Report when a security control is commented out, disabled by flag, wrapped in a no-op, or entirely absent where the code path clearly requires it (e.g., auth middleware not applied to a route that mutates data, rate limiting missing on login/OTP/export, helmet/csurf removed, cookie flags absent on session cookies, security headers absent).
- HTTP hardening headers are an exception to speculative-absence caution: if this chunk is the process HTTP bootstrap (NestFactory.create, express(), app.use chain, fastify()) and helmet()/CSP/HSTS are not applied in the visible middleware, report CWE-693 as its own finding. Authorization guards are not a substitute.
- For other absence classes, ONLY report when the provided lines give evidence the control is missing: an auth guard applied to sibling handlers but not this one, a commented-out middleware line, a route registered without its guard, a cookie set without Secure/HttpOnly. Do NOT report "missing X" speculatively when the chunk shows no such control ever existed and the framework may provide it elsewhere — state the evidence explicitly and lower confidence.
- Confidence for absence findings should reflect how strong the evidence is: commented-out control or clearly unguarded sensitive handler = 0.7-0.8; weaker inference = 0.65-0.69.

**DATA EXPOSURE & CRYPTO:**
- Hardcoded credentials (actual passwords/keys/tokens in source, NOT env var references)
- Default/weak credentials (CWE-798/CWE-1392/CWE-287): hardcoded default username/password pairs (admin/admin, admin/password, test/test), seeded admin accounts with known default passwords, no forced password change or lockout on default accounts, or password fallbacks to weak defaults
- Weak cryptography (MD5/SHA1 for security, Math.random for tokens, ECB mode, RSA < 2048 bits)
- IV/nonce reuse (CWE-329/CWE-323): static, predictable, or reused IVs/nonces across encryptions in GCM/CTR/CBC (e.g. hardcoded iv=, nonce reused across messages, counter restarted per message) — destroys confidentiality and enables forgery
- Unauthenticated encryption / padding-oracle patterns (CWE-353/CWE-209): AES-CBC or similar unauthenticated modes where ciphertext is attacker-controlled and the app reveals padding validity via distinct errors or timing, without Encrypt-then-MAC or an AEAD mode
- Weak key derivation / password storage (CWE-916/CWE-261): passwords or keys derived with fast unsalted hashes (md5, sha1, sha256 of password), low PBKDF2/script iterations, or bcrypt/argon2 cost below safe thresholds instead of an adaptive KDF
- Key reuse across algorithms/modes (CWE-323): the same key used for encryption and signing, or for multiple IV/nonce spaces, enabling cross-protocol attacks
- TLS verification bypass (rejectUnauthorized:false, verify=False, InsecureSkipVerify)
- Sensitive data in logs (PII, credentials, tokens written to log output)
- Full path disclosure (CWE-209): error responses, stack traces, or exception handlers leaking absolute filesystem paths, internal hostnames, or deployment paths; verbose error middleware returning server internals

**NETWORK & API SECURITY:**
- SSRF (user-controlled URLs passed to HTTP clients)
- CORS misconfiguration (wildcard origin with credentials, dynamic origin reflection without allowlist)
- GraphQL abuse (introspection in production, unbounded query depth, batching attacks)
- WebSocket security (missing origin validation on upgrade, no auth on WS connections)
- gRPC security (reflection enabled in production, missing TLS, no auth interceptors)
- Missing HTTP security headers (HSTS, CSP, X-Content-Type-Options)
- Unrestricted resource consumption: missing rate limits on login, password reset, OTP, search, export, upload, report generation, or AI endpoints
- Excessive data exposure: API returns password hashes, tokens, secrets, internal authorization fields, other tenants' IDs, or unfiltered related objects
- Config/secret-exposing endpoints (CWE-200/CWE-312): unauthenticated or weakly-protected endpoints that return DB connection strings, API keys, JWT secrets, SMTP credentials, or internal config (e.g. /api/config, /api/secrets, /config, /debug, /info, /health variants returning secrets), or serve .env/config files directly
- Web-server/server-config exposure: directory listing enabled (nginx autoindex on, Apache Options +Indexes) serving source, backups, or secrets; unrestricted HTTP methods on raw locations (nginx put.raw-style location, dav_methods PUT/DELETE, missing method allowlist) allowing file writes/deletion on the server

**DESERIALIZATION & FILE HANDLING:**
- Insecure deserialization (untrusted data passed to deserialize/pickle/eval)
- File upload exploits: missing server-side extension/type validation on upload endpoints (e.g. @UseInterceptors(FileInterceptor('file')), multer, busboy, formidable, fileUpload, UploadedFile) — no allowlist of extensions/MIME types, unfiltered filenames enabling path traversal or polyglot/writable-content upload, missing size limits
- Prototype pollution (user input merged into object prototypes, __proto__/constructor keys)
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
- In metadata when it is obvious from the chunk, set "findingLayer" to one of: "application-code" | "web-template" | "manifest-dependencies" | "container-build" | "ci-or-deploy-config".${SEVERITY_CALIBRATION_PROMPT}`;

interface LlmFinding {
  title: string;
  severity: string;
  description: string;
  filePath?: string;
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

  const controlFindings = scanMissingHardeningHeaders(ctx);
  if (controlFindings.length > 0 && ctx.onBatchFindings) {
    await ctx.onBatchFindings("SAST_LLM", controlFindings);
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
  const MAX_ADDITIONAL_POLICY_BATCHES = 5; // Cap at 5 × 8 = 40 additional policies max
  const allPolicies = await fetchEnabledPolicies(ctx.orgSettings.orgId);
  const inlinePolicies = allPolicies.slice(0, MAX_INLINE_POLICIES);
  const additionalPolicies = allPolicies.slice(
    MAX_INLINE_POLICIES,
    MAX_INLINE_POLICIES + MAX_ADDITIONAL_POLICY_BATCHES * ADDITIONAL_POLICY_BATCH_SIZE,
  );

  if (allPolicies.length > MAX_INLINE_POLICIES + additionalPolicies.length) {
    logger.warn(
      {
        total: allPolicies.length,
        processed: MAX_INLINE_POLICIES + additionalPolicies.length,
      },
      "Policy list truncated to prevent unbounded re-scan",
    );
  }
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

  const repoAnalysis = buildDeepRepoContext(ctx.workDir, ctx.fileList);
  const repoContextBlock = repoAnalysis.summary;

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
  // Maps "filePath:startLine-endLine" → chunk.content for pass-2 validation context
  const chunkContentMap = new Map<string, string>();

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
    const fileName = path.basename(filePath);

    if (BINARY_EXTENSIONS.has(ext)) continue;
    if (!FILE_EXTENSIONS[ext]) continue;

    const parts = filePath.split(path.sep);
    if (parts.some((p) => SKIP_DIRECTORIES.has(p))) continue;

    // Exclude config, data, and lock files from SAST
    if (SAST_EXCLUDED_EXTENSIONS.has(ext)) continue;
    if (DEPENDENCY_MANIFEST_FILES.has(fileName)) continue;

    try {
      const content = fs.readFileSync(fullPath, "utf-8");
      if (Buffer.byteLength(content, "utf8") > LLM_MAX_FILE_SIZE_BYTES) continue;
      if (content.trim().length === 0) continue;

      const fileChunks = chunkFile(content, filePath, chunkTokens, overlapTokens);
      for (const c of fileChunks) {
        chunkContentMap.set(`${c.filePath}:${c.startLine}-${c.endLine}`, c.content);
      }
      chunks.push(...fileChunks);
    } catch {
      continue;
    }
  }

  // Count unique files and total lines of code across all chunks
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

  // Pass 2: cross-file validation of pass-1 candidates
  const pass1Candidates = findings.filter((f) => f.metadata?.passPhase === 1);
  const pass1Confirmed = findings.filter((f) => f.metadata?.passPhase === 2);

  let validated: RawFinding[] = [...pass1Confirmed];
  if (pass1Candidates.length > 0) {
    ctx.onProgress?.(
      `LLM SAST: validating ${pass1Candidates.length} candidates with cross-file context...`,
    );
    const pass2 = await validateCandidatesPass2(
      client,
      ctx.orgSettings.llmModel,
      pass1Candidates,
      repoContextBlock,
      maxResponseTokens,
      chunkContentMap,
    );
    validated = [...validated, ...pass2];
    if (pass2.length > 0 && ctx.onBatchFindings) {
      await ctx.onBatchFindings("SAST_LLM", pass2);
    }
  }

  logger.info(
    {
      total: chunks.length,
      succeeded,
      failed,
      pass1: findings.length,
      pass2: validated.length,
      filesScanned: totalFiles,
      additionalPolicyPasses: Math.ceil(
        additionalPolicies.length / ADDITIONAL_POLICY_BATCH_SIZE,
      ),
    },
    "LLM SAST analysis complete",
  );

  if (validated.length > 0) {
    ctx.onProgress?.(`LLM SAST: ${validated.length} findings across ${totalFiles} files`);
  }

  return [...controlFindings, ...validated];
}

const PASS2_OUTPUT_MIN = 0.75; // Pass-2 confirms candidates; output must reach high confidence

async function validateCandidatesPass2(
  client: ReturnType<typeof createLlmClient>,
  model: string,
  candidates: RawFinding[],
  repoContextBlock: string,
  maxResponseTokens: number,
  chunkContentMap: Map<string, string> = new Map(),
): Promise<RawFinding[]> {
  const BATCH = 12;
  const validated: RawFinding[] = [];

  for (let i = 0; i < candidates.length; i += BATCH) {
    const batch = candidates.slice(i, i + BATCH);
    const payload = batch.map((c, idx) => {
      const chunkKey = `${c.filePath}:${c.startLine}-${c.endLine}`;
      const codeSnippet = chunkContentMap.get(chunkKey);
      return {
        index: idx,
        title: c.title,
        filePath: c.filePath,
        startLine: c.startLine,
        endLine: c.endLine,
        cweId: c.cweId,
        confidence: c.confidence,
        description: c.description?.slice(0, 600),
        metadata: c.metadata,
        // Include original code so the validator can re-examine it
        codeSnippet: codeSnippet
          ? codeSnippet.slice(0, 2000) // cap to ~500 tokens per candidate
          : undefined,
      };
    });

    try {
      const raw = await analyzeWithLlm(
        client,
        model,
        `${SYSTEM_PROMPT}\n\n${SAST_PASS2_PROMPT}`,
        `${repoContextBlock}\n\nCANDIDATES TO VALIDATE:\n${JSON.stringify(payload, null, 2)}`,
        { maxTokens: maxResponseTokens },
      );
      const parsed = parseLlmJsonResponse<{ findings: LlmFinding[] }>(raw, {
        findings: [],
      });

      for (const f of parsed.findings || []) {
        if (!f.title) continue; // Pass-2 SAST_PASS2_PROMPT already requires >= 0.80

        // Match LLM response findings to source candidates by normalized title first,
        // then by filePath + line proximity. Never fall back to positional index —
        // LLM may reorder, merge, or drop findings.
        const fTitle = f.title.toLowerCase().replace(/[^a-z0-9]+/g, "");
        let src: (typeof batch)[0] | undefined;
        let bestScore = 0;
        for (const c of batch) {
          const cTitle = (c.title || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
          if (cTitle === fTitle) { src = c; bestScore = 2; break; }
          if (cTitle.includes(fTitle) || fTitle.includes(cTitle)) {
            if (bestScore < 1) { src = c; bestScore = 1; }
          }
        }
        // If only a fuzzy match, tighten with filePath proximity
        if (src && bestScore < 2 && src.filePath !== f.filePath) {
          src = batch.find(c => c.filePath === f.filePath) || src;
        }
        if (!src) continue; // orphan finding from LLM — skip

        const base: RawFinding = applySeverityCalibration({
          scanner: "SAST_LLM",
          severity: parseSeverity(f.severity),
          title: f.title,
          description: f.description,
          filePath: src?.filePath,
          startLine: f.startLine,
          endLine: f.endLine,
          cweId: f.cweId,
          confidence: f.confidence,
          ruleId: f.cweId || "CWE-UNKNOWN",
          metadata: {
            ...(f.metadata || {}),
            passPhase: 2,
          },
        });
        validated.push(
          enrichFinding(base, base.metadata as Record<string, unknown>, {
            whatIsWrong: f.title,
            where: `${src?.filePath}:${f.startLine}`,
            whyExploitable:
              (f.metadata?.attackPath as string) || f.description,
            fix:
              (f.metadata?.remediation as string) ||
              f.recommendation ||
              "Apply secure coding fix for this sink/path.",
          }),
        );
      }
    } catch (err) {
      logger.error({ err }, "SAST pass-2 validation batch failed");
    }
  }

  return validated;
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

    const pass1Floor = 0.65; // Minimum threshold; findings 0.65-0.74 are pass-1 candidates for pass-2 validation

    const allFindings = (parsed.findings || []).filter(
      (f) => f.title && f.severity,
    );
    const filtered = allFindings
      .filter((f) => {
        const confidence = f.confidence ?? 0;
        // Log near-threshold findings for visibility
        if (confidence >= 0.65 && confidence < pass1Floor) {
          logger.debug(
            {
              filePath: chunk.filePath,
              title: f.title,
              confidence,
            },
            "Filtered near-threshold finding (confidence 0.65-0.75 requires pass-2 validation)",
          );
        }
        return confidence >= pass1Floor;
      })
      .filter((f) => {
        // Reject findings with non-application-code layer metadata
        // (manifest-dependencies, container-build, ci-or-deploy-config should not be SAST)
        const layer = (f.metadata?.findingLayer as string | null | undefined);
        if (
          layer === "manifest-dependencies" ||
          layer === "container-build" ||
          layer === "ci-or-deploy-config"
        ) {
          logger.warn(
            {
              filePath: chunk.filePath,
              title: f.title,
              layer,
            },
            "Rejecting finding with non-SAST layer classification",
          );
          return false;
        }
        return true;
      });

    return filtered
      .filter((f) => {
        // SAST must NOT report CWE-798 (hardcoded credentials)
        // Those are exclusively handled by SECRETS_LLM scanner
        const isCwe798 = f.cweId === "CWE-798";
        const isCredentialByTitle =
          /hardcoded|embedded\s+secret|plaintext\s+(?:password|secret|token)|static\s+(?:api\s+key|secret|credential)|exposed\s+credential|stored\s+(?:bearer|token|secret)|leaked?\s+(?:key|token|secret|credential)/i.test(
            f.title,
          );
        const isCredentialByMeta = (f.metadata?.weaknessClass as string | undefined)
          ?.toLowerCase()
          .includes("credential");

        if (isCwe798 || isCredentialByTitle || isCredentialByMeta) {
          logger.debug(
            {
              filePath: chunk.filePath,
              title: f.title,
              cweId: f.cweId,
            },
            "Filtering CWE-798 (hardcoded credential) from SAST — exclusive to SECRETS scanner",
          );
          return false;
        }
        return true;
      })
      .map((f) => {
        const titleLower = f.title.toLowerCase();
        const isPolicy =
          titleLower.includes("policy") || titleLower.includes("policy:");
        const matchedPolicy = policyNames.find((name) =>
          titleLower.includes(name.toLowerCase()),
        );

        const passPhase =
          (f.confidence ?? 0) >= LLM_MIN_CONFIDENCE_DEFAULT ? 2 : 1;
        const meta: Record<string, unknown> = {
          ...(f.metadata || {}),
          passPhase,
          remediation:
            f.recommendation ||
            (f.metadata?.remediation as string | undefined),
          ...(matchedPolicy
            ? { policyName: matchedPolicy, type: "policy-violation" }
            : {}),
        };

      const exploitabilityScore = calculateExploitabilityScore(
        f.confidence ?? pass1Floor,
        f.severity,
        f.metadata,
      );

      const owaspCategory = getOwasp2024Category(f.cweId);
      const owaspApiCategory = getOwaspApiCategory(f.cweId);
      const owaspLlmCategory = getOwaspLlmCategory(f.cweId);

      const base: RawFinding = applySeverityCalibration({
        scanner: "SAST_LLM" as const,
        severity: parseSeverity(f.severity),
        title: f.title,
        description: f.description,
        filePath: chunk.filePath,
        startLine: f.startLine,
        endLine: f.endLine,
        cweId: f.cweId,
        confidence: f.confidence ?? pass1Floor,
        ruleId: isPolicy
          ? `POLICY-${matchedPolicy || "CUSTOM"}`
          : f.cweId || "CWE-UNKNOWN",
        metadata: {
          ...meta,
          owasp2024: owaspCategory,
          owaspApi: owaspApiCategory,
          owaspLlm: owaspLlmCategory,
          exploitability: {
            score: exploitabilityScore.score,
            label: getExploitabilityLabel(exploitabilityScore.score),
            attackVector: exploitabilityScore.attackVector,
            attackComplexity: exploitabilityScore.attackComplexity,
            privilegesRequired: exploitabilityScore.privilegesRequired,
            userInteraction: exploitabilityScore.userInteraction,
            scope: exploitabilityScore.scope,
          },
        },
      });

      if (passPhase === 2) {
        return enrichFinding(base, base.metadata as Record<string, unknown>, {
          whatIsWrong: f.title,
          where: `${chunk.filePath}:${f.startLine}-${f.endLine}`,
          whyExploitable: (f.metadata?.attackPath as string) ||
            f.description.split("\n")[0],
          impact: f.metadata?.impact as string | undefined,
          fix:
            f.recommendation ||
            (f.metadata?.remediation as string) ||
            "Remediate per recommendation.",
        });
      }
      return base;
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

