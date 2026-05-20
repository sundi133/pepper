import { PatternRule } from "../../types";

export const owaspRules: PatternRule[] = [
  {
    id: "OWASP-A01-IDOR-001",
    title: "Potential IDOR from direct object lookup by request ID",
    description:
      "A resource appears to be fetched by a user-controlled ID without an obvious owner, tenant, or organization constraint on the same query. Verify authorization is scoped to the authenticated principal.",
    severity: "HIGH",
    cweId: "CWE-639",
    languages: ["*"],
    pattern:
      /(?:findUnique|findById|find_one|findOne|get)\s*\([^)]*(?:params|param|query|body|request|req\.|ctx\.|input).*(?:id|Id|ID)/i,
    negative:
      /(?:userId|ownerId|tenantId|orgId|organizationId|accountId|projectId|workspaceId|where:.*(?:user|owner|tenant|org|organization|account|workspace))/i,
  },
  {
    id: "OWASP-A01-AUTHZ-001",
    title: "Admin or role value trusted from request input",
    description:
      "Authorization-sensitive fields such as role, admin flags, permissions, or scopes should be derived server-side, not trusted from request input.",
    severity: "HIGH",
    cweId: "CWE-269",
    languages: ["*"],
    pattern:
      /(?:role|roles|isAdmin|admin|permission|permissions|scope|scopes)\s*[:=]\s*(?:req\.|request\.|ctx\.|input|body|params|query|\$_POST|\$_GET)/i,
    negative: /(?:validate|schema|zod|joi|yup|allowlist|whitelist|sanitize|test|spec)/i,
  },
  {
    id: "OWASP-A01-MASSASSIGN-001",
    title: "Mass assignment from request body",
    description:
      "Passing an entire request body into create/update operations can let attackers set protected fields such as role, owner, price, tenant, or status. Use an explicit allowlist.",
    severity: "HIGH",
    cweId: "CWE-915",
    languages: ["*"],
    pattern:
      /(?:create|update|save|insert|assign|merge)\s*\([^)]*(?:req\.body|request\.body|await\s+req\.json\(\)|body|params)\b/i,
    negative:
      /(?:pick|omit|allowlist|whitelist|safeParse|parse|validate|schema|DTO|dto|serializer|test|spec)/i,
  },
  {
    id: "OWASP-A02-JWT-001",
    title: "JWT decoded without signature verification",
    description:
      "Decoding JWTs without verifying the signature allows attackers to forge claims such as user ID, role, tenant, or scope.",
    severity: "CRITICAL",
    cweId: "CWE-347",
    languages: ["*"],
    pattern: /\b(?:jwt|JWT|JsonWebToken)\.decode\s*\(/,
    negative: /(?:verify|test|spec|mock)/i,
  },
  {
    id: "OWASP-A02-JWT-002",
    title: "JWT verification accepts weak or missing algorithms",
    description:
      "Accepting 'none' or caller-controlled JWT algorithms can enable token forgery or algorithm confusion attacks.",
    severity: "CRITICAL",
    cweId: "CWE-347",
    languages: ["*"],
    pattern:
      /(?:algorithms?\s*[:=]\s*\[[^\]]*['"]none['"]|algorithm\s*[:=]\s*(?:req\.|request\.|body|params|query))/i,
  },
  {
    id: "OWASP-A04-RACE-001",
    title: "Check-then-act update without transaction",
    description:
      "Security or business checks followed by a state-changing write can be race-prone if not protected by a transaction, lock, unique constraint, or optimistic version check.",
    severity: "MEDIUM",
    cweId: "CWE-362",
    languages: ["*"],
    pattern:
      /(?:if\s*\(.*(?:balance|quota|limit|stock|inventory|status|owner|role|permission|token).*\)|(?:balance|quota|stock|inventory|status)\s*[<>!=]=?)/i,
    negative: /(?:transaction|lock|mutex|atomic|version|optimistic|forUpdate|SELECT .*FOR UPDATE|test|spec)/i,
  },
  {
    id: "OWASP-A05-CORS-001",
    title: "Credentialed CORS may trust arbitrary origins",
    description:
      "Reflecting arbitrary origins or allowing credentials with broad CORS policy can expose authenticated APIs cross-origin.",
    severity: "HIGH",
    cweId: "CWE-942",
    languages: ["*"],
    pattern:
      /(?:credentials\s*:\s*true|Access-Control-Allow-Credentials).*?(?:origin\s*:\s*true|origin\s*:\s*['"]\*|Access-Control-Allow-Origin.*\*)/i,
  },
  {
    id: "OWASP-A06-UNPINNED-001",
    title: "Unpinned external CI/CD action or container reference",
    description:
      "Unpinned third-party actions or container images can change unexpectedly and introduce supply-chain compromise. Pin to immutable SHAs or digests.",
    severity: "MEDIUM",
    cweId: "CWE-494",
    languages: ["yaml", "*"],
    pattern: /^\s*(?:uses|image):\s*[^@\s:]+\/[^@\s:]+(?:@(?:main|master|latest|v\d+)|:latest)?\s*$/i,
    negative: /@(?:[a-f0-9]{40,64}|sha256:)|(?:actions\/checkout@v[0-9]+)$/i,
  },
  {
    id: "OWASP-A07-MFA-001",
    title: "Authentication flow appears to mark MFA as trusted from request",
    description:
      "MFA completion or trust state should be verified server-side. Trusting request-controlled MFA flags can bypass multi-factor authentication.",
    severity: "HIGH",
    cweId: "CWE-287",
    languages: ["*"],
    pattern:
      /(?:mfa|otp|totp|twoFactor|two_factor|2fa).*(?:verified|passed|trusted|complete)\s*[:=]\s*(?:true|req\.|request\.|body|params|query)/i,
    negative: /(?:verify|validate|compare|check|test|spec|mock)/i,
  },
  {
    id: "OWASP-A08-WEBHOOK-001",
    title: "Webhook handler without visible signature verification",
    description:
      "Webhook endpoints must verify provider signatures or HMACs before processing events. Missing verification can allow forged events and replay attacks.",
    severity: "HIGH",
    cweId: "CWE-345",
    languages: ["*"],
    pattern: /(?:webhook|stripe|github|gitlab|slack|paypal).*(?:handler|route|post|event)/i,
    negative: /(?:signature|signing_secret|hmac|verify|constructEvent|x-hub-signature|x-gitlab-token|test|spec)/i,
  },
  {
    id: "OWASP-A09-LOG-001",
    title: "Sensitive token or credential logged",
    description:
      "Logging secrets, tokens, cookies, authorization headers, or passwords can expose credentials through log aggregation and incident tooling.",
    severity: "HIGH",
    cweId: "CWE-532",
    languages: ["*"],
    pattern:
      /(?:console\.log|logger\.(?:info|debug|warn|error)|print|printf|log\.)\s*\([^)]*(?:password|passwd|secret|token|authorization|cookie|api[_-]?key|credential)/i,
    negative: /(?:redact|mask|masked|hash|test|spec|mock)/i,
  },
  {
    id: "OWASP-API4-RATELIMIT-001",
    title: "Authentication or expensive endpoint without visible rate limiting",
    description:
      "Login, password reset, token, upload, search, and export endpoints should have rate limits or abuse controls to prevent brute force and resource exhaustion.",
    severity: "MEDIUM",
    cweId: "CWE-770",
    languages: ["*"],
    pattern:
      /(?:login|signin|password[-_]?reset|forgot[-_]?password|token|otp|upload|export|search).*(?:post|handler|route|endpoint|controller)/i,
    negative: /(?:rateLimit|rate_limit|throttle|quota|limiter|slowDown|captcha|test|spec)/i,
  },
  {
    id: "OWASP-LLM01-PROMPT-001",
    title: "Untrusted input sent to LLM without instruction isolation",
    description:
      "Passing raw user-controlled content to an LLM without prompt-injection boundaries, tool restrictions, or output validation can allow indirect prompt injection.",
    severity: "MEDIUM",
    cweId: "CWE-20",
    languages: ["*"],
    pattern:
      /(?:chat\.completions|responses\.create|generateContent|invoke|complete|analyzeWithLlm)\s*\([^)]*(?:req\.|request\.|body|params|query|input|prompt)/i,
    negative: /(?:sanitize|validate|schema|guardrail|policy|tool_choice|response_format|test|spec)/i,
  },
];
