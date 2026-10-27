import type { RawFinding } from "@/scanners/types";
import { isTestLikePath } from "@/lib/test-paths";

export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

const ORDER: SeverityLevel[] = [
  "INFO",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
];

const RANK: Record<SeverityLevel, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/** CWE → baseline severity (exploitability + typical impact). */
const CWE_BASELINE: Record<string, SeverityLevel> = {
  "CWE-20": "MEDIUM",
  "CWE-22": "HIGH",
  "CWE-77": "CRITICAL",
  "CWE-78": "CRITICAL",
  "CWE-79": "HIGH",
  "CWE-89": "CRITICAL",
  "CWE-90": "HIGH",
  "CWE-91": "HIGH",
  "CWE-94": "CRITICAL",
  "CWE-119": "HIGH",
  "CWE-200": "MEDIUM",
  "CWE-287": "HIGH",
  "CWE-306": "HIGH",
  "CWE-311": "MEDIUM",
  "CWE-319": "MEDIUM",
  "CWE-326": "MEDIUM",
  "CWE-327": "MEDIUM",
  "CWE-328": "LOW",
  "CWE-352": "MEDIUM",
  "CWE-16": "MEDIUM",
  "CWE-693": "MEDIUM",
  "CWE-400": "MEDIUM",
  "CWE-502": "CRITICAL",
  "CWE-601": "MEDIUM",
  "CWE-611": "HIGH",
  "CWE-639": "HIGH",
  "CWE-732": "HIGH",
  "CWE-798": "CRITICAL",
  "CWE-862": "HIGH",
  "CWE-863": "HIGH",
  "CWE-917": "HIGH",
  "CWE-918": "HIGH",
  "CWE-1333": "MEDIUM",
};

const WEAKNESS_BASELINE: Record<string, SeverityLevel> = {
  "command injection": "CRITICAL",
  "code injection": "CRITICAL",
  "sql injection": "CRITICAL",
  "sqli": "CRITICAL",
  rce: "CRITICAL",
  "remote code execution": "CRITICAL",
  "server-side request forgery": "HIGH",
  ssrf: "HIGH",
  "path traversal": "HIGH",
  xss: "HIGH",
  "cross-site scripting": "HIGH",
  idor: "HIGH",
  "broken access control": "HIGH",
  "authentication bypass": "CRITICAL",
  "hardcoded credential": "CRITICAL",
  "hardcoded secret": "CRITICAL",
  "secret exposure": "CRITICAL",
  "insecure deserialization": "CRITICAL",
  "prototype pollution": "HIGH",
  ssti: "HIGH",
  "template injection": "HIGH",
  "weak cryptography": "MEDIUM",
  "missing authorization": "HIGH",
  "missing authentication": "HIGH",
  "security misconfiguration": "MEDIUM",
  "information disclosure": "MEDIUM",
  "log injection": "LOW",
  "missing security header": "LOW",
  "rate limiting": "MEDIUM",
  "policy violation": "HIGH",
  "race condition": "HIGH",
  "double-spend": "HIGH",
  "double spend": "HIGH",
  "business logic": "HIGH",
  "workflow bypass": "HIGH",
  "privilege escalation": "HIGH",
  "multi-tenant": "HIGH",
  "tenant isolation": "HIGH",
  "trust boundary": "HIGH",
  "parameter tampering": "MEDIUM",
  "mass assignment": "HIGH",
  csrf: "MEDIUM",
  "cross-site request forgery": "MEDIUM",
};

/**
 * Keys tried longest first so the most specific class wins ("missing
 * security header" before "security"), each matched as whole words so a short
 * key never fires inside another word ("rce" in "force", "resource", "source").
 */
const WEAKNESS_KEYS = Object.keys(WEAKNESS_BASELINE)
  .sort((a, b) => b.length - a.length)
  .map((key) => ({
    key,
    re: new RegExp(`(?:^|[^a-z0-9])${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:[^a-z0-9]|$)`),
  }));

/** An actual secret literal in source, not a finding that merely mentions a token or password. */
const HARDCODED_CREDENTIAL =
  /\bhard-?coded\b|\bembedded\s+(?:secret|credential|key|password|token)\b|\bplaintext\s+(?:password|secret|credential|api\s*key)\b|\bsecret\s+(?:exposure|literal)\b|\bleaked\s+(?:key|secret|token|credential)\b/i;

function isHardcodedCredential(weaknessClass: string, cweId?: string | null): boolean {
  return normalizeCwe(cweId) === "CWE-798" || HARDCODED_CREDENTIAL.test(weaknessClass);
}

function normalizeCwe(cweId?: string | null): string {
  if (!cweId) return "";
  const normalized = cweId.toUpperCase().replace(/^CWE[-\s]*/i, "CWE-");
  return normalized.startsWith("CWE-") ? normalized : `CWE-${normalized}`;
}

function shift(level: SeverityLevel, by: number): SeverityLevel {
  const idx = Math.max(0, Math.min(ORDER.length - 1, RANK[level] + by));
  return ORDER[idx];
}

/** A leading "CRITICAL:" / "HIGH (model rated …):" label on a justification. */
const SEVERITY_LABEL_PREFIX =
  /^\s*(?:CRITICAL|HIGH|MEDIUM|LOW|INFO)\b(?:\s*\([^)]*\))?\s*[:—–-]\s*/i;


export const SEVERITY_CALIBRATION_PROMPT = `
**SEVERITY CALIBRATION (MANDATORY — must match vulnerability class)**

Assign severity using a TWO-STEP method. The "severity" field MUST align with weakness class and CWE — do NOT label everything CRITICAL.

**Step 1 — Classify weaknessClass** (pick one): Command Injection | SQL Injection | XSS | SSRF | Path Traversal | IDOR | Auth Bypass | CSRF | Hardcoded Credential | Weak Crypto | Deserialization | SSTI | Security Misconfiguration | Information Disclosure | Business Logic | Policy Violation | Other
Use "Hardcoded Credential" ONLY for a secret value written in the source. A missing/weak CSRF token, a weak password policy, or a JWT that does not expire is NOT a hardcoded credential.

**Step 2 — Map to severity using this matrix.** The matrix gives the default for the class. Move ONE level up or down from it only for reasons visible in the code: who the attacker is (anonymous vs logged-in vs admin-only), what they reach (one user's data vs all tenants, read vs write vs code execution), and preconditions. State that reason in severityJustification. A severity more than one level away from the class default is corrected automatically, and Policy Violation findings take the severity configured for the policy.

| Class | Default severity | Raise to CRITICAL only when |
|-------|------------------|-----------------------------|
| Command Injection / RCE / Code Injection | CRITICAL | User input reaches exec/spawn/eval with visible path |
| SQL Injection | CRITICAL | Query built via string concat with user input |
| Auth Bypass / Missing auth on sensitive route | CRITICAL | Admin/payment/data route has no auth check |
| Hardcoded Credential (CWE-798) | CRITICAL | Live token/password/key literal in source (not env var name) |
| Deserialization of untrusted data | CRITICAL | Clear untrusted → deserialize path |
| XSS (stored/reflected) | HIGH | Output reaches HTML/DOM without encoding |
| SSRF | HIGH | User-controlled URL reaches HTTP client |
| IDOR / Broken Access Control | HIGH | Object ID from user without ownership check |
| Path Traversal | HIGH | User path segment in file read/write |
| Weak Crypto (MD5/SHA1 for passwords, Math.random tokens) | MEDIUM | Used for security-sensitive purpose |
| Security Misconfiguration (CORS, headers, debug) | MEDIUM | Production-reachable misconfig |
| Information Disclosure | MEDIUM | Sensitive fields logged or returned |
| Missing rate limit / verbose errors | LOW | Non-auth endpoints only |
| Style / best-practice only | LOW or omit | No exploitable path |

**Downgrade rules (apply after matrix):**
- Confidence 0.65–0.74: cap at HIGH (never CRITICAL)
- Confidence 0.75–0.79: cap at HIGH unless Hardcoded Credential or live RCE sink is visible
- Route AND parameter both unknown: cap injection/RCE at HIGH (not CRITICAL)
- Test/fixture/mock path: reduce one level (CRITICAL→HIGH, HIGH→MEDIUM)
- Theoretical/framework-mitigated issue: MEDIUM or LOW — explain in metadata.confidenceReason

**metadata required for severity audit:**
- "weaknessClass": exact class from step 1
- "attackerAccess": "anonymous" | "authenticated" | "privileged" (admin/operator only) | "local" | null when not visible
- "severityJustification": one sentence citing class + evidence (e.g. "CRITICAL: CWE-78, user code param passed to subprocess.check_output line 42")
- Do NOT put a different severity in title/description than the "severity" field
`;

export function parseSeverity(raw?: string | null): SeverityLevel {
  const upper = (raw || "").trim().toUpperCase();
  if (ORDER.includes(upper as SeverityLevel)) return upper as SeverityLevel;
  if (/crit/i.test(raw || "")) return "CRITICAL";
  if (/high/i.test(raw || "")) return "HIGH";
  if (/med/i.test(raw || "")) return "MEDIUM";
  if (/low/i.test(raw || "")) return "LOW";
  if (/info/i.test(raw || "")) return "INFO";
  return "MEDIUM";
}

function clampSeverity(
  level: SeverityLevel,
  max: SeverityLevel,
): SeverityLevel {
  return RANK[level] > RANK[max] ? max : level;
}

function baselineFromCwe(cweId?: string | null): SeverityLevel | undefined {
  const key = normalizeCwe(cweId);
  return key ? CWE_BASELINE[key] : undefined;
}

function baselineFromWeakness(
  weaknessClass?: string | null,
  title?: string,
): SeverityLevel | undefined {
  const text = `${weaknessClass || ""} ${title || ""}`.toLowerCase();
  const hit = WEAKNESS_KEYS.find(({ re }) => re.test(text));
  return hit ? WEAKNESS_BASELINE[hit.key] : undefined;
}

function baselineFromScanner(scanner?: string): SeverityLevel | undefined {
  if (scanner?.startsWith("SECRETS")) return "CRITICAL";
  if (scanner === "SCA" || scanner === "MALICIOUS_PKG") return "HIGH";
  return undefined;
}

function isContextLimited(meta: Record<string, unknown>): boolean {
  const route = meta.route ?? meta.endpoint;
  const param = meta.parameter;
  const hasRoute = typeof route === "string" && route.trim().length > 0;
  const hasParam = typeof param === "string" && param.trim().length > 0;
  return !hasRoute && !hasParam;
}

/** Confidence, context, access and test-path caps; each one that applies is recorded. */
function applyCaps(
  level: SeverityLevel,
  confidence: number,
  contextLimited: boolean,
  testPath: boolean,
  weaknessClass: string,
  cweId: string | null | undefined,
  attackerAccess: string | undefined,
  reasons: string[],
): SeverityLevel {
  let severity = level;
  const cap = (max: SeverityLevel, why: string) => {
    if (RANK[severity] > RANK[max]) {
      severity = max;
      reasons.push(why);
    }
  };
  if (confidence < 0.7) cap("MEDIUM", `confidence ${confidence.toFixed(2)}`);
  else if (confidence < 0.75) cap("HIGH", `confidence ${confidence.toFixed(2)}`);
  if (
    contextLimited &&
    !isHighImpactWeakness(weaknessClass, cweId || undefined) &&
    /injection|rce|command|sql|xss|ssrf/i.test(weaknessClass)
  ) {
    cap("HIGH", "route and parameter not confirmed");
  }
  if (attackerAccess === "privileged") cap("HIGH", "requires admin/operator access");
  if (attackerAccess === "local") cap("MEDIUM", "requires local access");
  if (testPath && severity !== "INFO") {
    severity = shift(severity, -1);
    reasons.push("test/fixture path");
  }
  return severity;
}

function isHighImpactWeakness(weakness?: string, cweId?: string): boolean {
  const w = (weakness || "").toLowerCase();
  if (isHardcodedCredential(w, cweId)) return true;
  if (/command injection|\brce\b|sql injection|auth bypass|deserial/.test(w)) {
    return true;
  }
  return false;
}

export interface CalibrateSeverityInput {
  llmSeverity?: string | null;
  cweId?: string | null;
  weaknessClass?: string | null;
  title?: string;
  confidence?: number | null;
  scanner?: string;
  filePath?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Final severity for a finding.
 *
 * The reported severity (the model's, or a rule's) is the starting point, not
 * a suggestion to overwrite: it carries context the class table cannot see
 * (admin-only route, read vs write, one user vs every tenant). The CWE /
 * weakness-class baseline only keeps it within one level of the class
 * default, which stops both "everything is CRITICAL" and an exploitable
 * injection labelled LOW. Fixed rules follow: misconfiguration-type classes
 * top out at MEDIUM, a hardcoded secret is CRITICAL when confident, a policy
 * violation uses the policy's configured severity, then the confidence,
 * context, access and test-path caps.
 */
export function calibrateSeverity(
  input: CalibrateSeverityInput,
): {
  severity: SeverityLevel;
  justification: string;
  llmSeverity: SeverityLevel;
  adjusted: boolean;
  weaknessClass: string;
} {
  const meta = input.metadata || {};
  const llmSeverity = parseSeverity(input.llmSeverity);
  const weaknessClass =
    (input.weaknessClass || (meta.weaknessClass as string) || "").trim() ||
    inferWeaknessClass(input);

  const fromCwe = baselineFromCwe(input.cweId);
  const fromWeakness = baselineFromWeakness(weaknessClass, input.title);
  const baseline: SeverityLevel | undefined =
    fromCwe && fromWeakness
      ? RANK[fromCwe] >= RANK[fromWeakness] ? fromCwe : fromWeakness
      : fromCwe || fromWeakness || baselineFromScanner(input.scanner);

  const reasons: string[] = [];
  let severity: SeverityLevel = llmSeverity;
  const confidence = input.confidence ?? 0.8;

  if (baseline) {
    const lo = shift(baseline, -1);
    const hi = shift(baseline, 1);
    const label = normalizeCwe(input.cweId) || weaknessClass;
    if (RANK[severity] > RANK[hi]) {
      severity = hi;
      reasons.push(`${label} defaults to ${baseline}`);
    } else if (RANK[severity] < RANK[lo]) {
      severity = lo;
      reasons.push(`${label} defaults to ${baseline}`);
    }
  }

  if (/misconfig|header|verbose|rate limit|info(?:rmation)? disclosure/i.test(weaknessClass)) {
    const before = severity;
    severity = clampSeverity(severity, "MEDIUM");
    if (severity !== before) reasons.push(`${weaknessClass} tops out at MEDIUM`);
  }

  if (isHardcodedCredential(weaknessClass, input.cweId)) {
    const forced: SeverityLevel = confidence >= 0.8 ? "CRITICAL" : "HIGH";
    if (forced !== severity) reasons.push(`hardcoded credential at confidence ${confidence.toFixed(2)}`);
    severity = forced;
  }

  const policySev = (meta.policySeverity as string) || (meta.severity as string);
  const isPolicy = meta.type === "policy-violation" || /policy/i.test(weaknessClass);
  if (isPolicy && policySev) {
    const configured = parseSeverity(policySev);
    if (configured !== severity) reasons.push("severity configured for the policy");
    severity = configured;
  }

  severity = applyCaps(
    severity,
    confidence,
    isContextLimited(meta),
    isTestLikePath(input.filePath),
    weaknessClass,
    input.cweId,
    typeof meta.attackerAccess === "string" ? meta.attackerAccess.toLowerCase() : undefined,
    reasons,
  );

  const adjusted = llmSeverity !== severity;
  // The model's own sentence keeps its evidence, but its severity label is
  // replaced so the text never contradicts the stored severity.
  const modelText = ((meta.severityJustification as string) || "")
    .trim()
    .replace(SEVERITY_LABEL_PREFIX, "");
  const justification = adjusted
    ? `${severity} (model rated ${llmSeverity}; ${reasons.join("; ") || "calibrated"})${modelText ? `: ${modelText}` : ""}`
    : modelText
      ? `${severity}: ${modelText}`
      : buildJustification({
          severity,
          weaknessClass,
          cweId: input.cweId,
          confidence,
          contextLimited: isContextLimited(meta),
          testPath: Boolean(isTestLikePath(input.filePath)),
        });

  return {
    severity,
    justification,
    llmSeverity,
    adjusted,
    weaknessClass,
  };
}

function inferWeaknessClass(input: CalibrateSeverityInput): string {
  const text = `${input.title || ""} ${input.cweId || ""}`.toLowerCase();
  if (isHardcodedCredential(text, input.cweId)) return "Hardcoded Credential";
  if (/\bcsrf\b|cross-site request forgery|cwe-352/.test(text)) return "CSRF";
  if (/command injection|\brce\b|remote code execution|os\.system|subprocess/.test(text)) return "Command Injection";
  if (/sql injection|\bsqli\b/.test(text)) return "SQL Injection";
  if (/\bxss\b|cross-site scripting/.test(text)) return "XSS";
  if (/\bssrf\b|server-side request forgery/.test(text)) return "SSRF";
  if (/\bidor\b|access control|authori[sz]ation/.test(text)) return "IDOR";
  if (/path traversal/.test(text)) return "Path Traversal";
  if (/deserial/.test(text)) return "Deserialization";
  if (/\bpolicy\b/.test(text)) return "Policy Violation";
  return "Other";
}

function buildJustification(params: {
  severity: SeverityLevel;
  weaknessClass: string;
  cweId?: string | null;
  confidence: number;
  contextLimited: boolean;
  testPath: boolean;
}): string {
  const parts = [
    `${params.severity}: ${params.weaknessClass}`,
    params.cweId ? params.cweId : null,
    params.contextLimited ? "exploit path partially confirmed" : "evidence in cited code",
    params.confidence < 0.8 ? `confidence ${params.confidence.toFixed(2)}` : null,
    params.testPath ? "test/fixture path (severity reduced)" : null,
  ].filter(Boolean);
  return parts.join("; ");
}

/** Apply calibrated severity to a raw finding before DB insert. */
export function applySeverityCalibration(finding: RawFinding): RawFinding {
  const meta = (finding.metadata || {}) as Record<string, unknown>;
  const result = calibrateSeverity({
    llmSeverity: finding.severity,
    cweId: finding.cweId,
    weaknessClass: (meta.weaknessClass as string) || undefined,
    title: finding.title,
    confidence: finding.confidence,
    scanner: finding.scanner,
    filePath: finding.filePath,
    metadata: meta,
  });

  return {
    ...finding,
    severity: result.severity,
    metadata: {
      ...meta,
      weaknessClass: result.weaknessClass,
      severityJustification: result.justification,
      llmSeverity: result.llmSeverity,
      severityCalibrated: result.adjusted,
    },
  };
}

/** @deprecated Use parseSeverity — kept for scanner normalizeSeverity helpers */
export function normalizeSeverity(s: string): SeverityLevel {
  return parseSeverity(s);
}
