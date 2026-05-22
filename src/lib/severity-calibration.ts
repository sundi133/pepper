import type { RawFinding } from "@/scanners/types";

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
  "CWE-400": "MEDIUM",
  "CWE-502": "CRITICAL",
  "CWE-611": "HIGH",
  "CWE-639": "HIGH",
  "CWE-798": "CRITICAL",
  "CWE-918": "HIGH",
  "CWE-917": "HIGH",
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
};

const TEST_PATH =
  /(?:^|\/)(?:test|tests|spec|specs|__tests__|fixtures?|mocks?|examples?|demo|sample)(?:\/|$)|\.(?:test|spec)\.[jt]sx?$/i;

export const SEVERITY_CALIBRATION_PROMPT = `
**SEVERITY CALIBRATION (MANDATORY — must match vulnerability class)**

Assign severity using a TWO-STEP method. The "severity" field MUST align with weakness class and CWE — do NOT label everything CRITICAL.

**Step 1 — Classify weaknessClass** (pick one): Command Injection | SQL Injection | XSS | SSRF | Path Traversal | IDOR | Auth Bypass | Hardcoded Credential | Weak Crypto | Deserialization | SSTI | Security Misconfiguration | Information Disclosure | Business Logic | Policy Violation | Other

**Step 2 — Map to severity using this matrix:**

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
  if (!cweId) return undefined;
  const normalized = cweId.toUpperCase().replace(/^CWE[-\s]*/i, "CWE-");
  const key = normalized.startsWith("CWE-") ? normalized : `CWE-${normalized}`;
  return CWE_BASELINE[key];
}

function baselineFromWeakness(
  weaknessClass?: string | null,
  title?: string,
): SeverityLevel | undefined {
  const text = `${weaknessClass || ""} ${title || ""}`.toLowerCase();
  for (const [key, sev] of Object.entries(WEAKNESS_BASELINE)) {
    if (text.includes(key)) return sev;
  }
  return undefined;
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

function applyCaps(
  level: SeverityLevel,
  confidence: number,
  contextLimited: boolean,
  testPath: boolean,
  weaknessClass: string,
  cweId?: string | null,
): SeverityLevel {
  let severity = level;
  if (confidence < 0.75) severity = clampSeverity(severity, "HIGH");
  if (confidence < 0.7) severity = clampSeverity(severity, "MEDIUM");
  if (
    contextLimited &&
    !isHighImpactWeakness(weaknessClass, cweId || undefined) &&
    /injection|rce|command|sql|xss|ssrf/i.test(weaknessClass)
  ) {
    severity = clampSeverity(severity, "HIGH");
  }
  if (testPath) {
    const down: SeverityLevel[] = [
      "INFO",
      "LOW",
      "MEDIUM",
      "HIGH",
      "CRITICAL",
    ];
    const idx = down.indexOf(severity);
    severity = idx > 0 ? down[idx - 1] : severity;
  }
  return severity;
}

function isHighImpactWeakness(weakness?: string, cweId?: string): boolean {
  const w = (weakness || "").toLowerCase();
  if (/hardcoded|credential|secret/.test(w)) return true;
  if (cweId === "CWE-798") return true;
  if (/command injection|rce|sql injection|auth bypass|deserial/.test(w)) {
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
  const fromScanner = baselineFromScanner(input.scanner);

  let baseline: SeverityLevel =
    fromCwe || fromWeakness || fromScanner || llmSeverity;

  if (fromCwe && fromWeakness) {
    baseline =
      RANK[fromCwe] >= RANK[fromWeakness] ? fromCwe : fromWeakness;
  }

  let severity: SeverityLevel = baseline;
  const confidence = input.confidence ?? 0.8;
  const testPath = Boolean(input.filePath && TEST_PATH.test(input.filePath));
  const contextLimited = isContextLimited(meta);

  if (/misconfig|header|verbose|rate limit|info disclosure/i.test(weaknessClass)) {
    severity = clampSeverity(severity, "MEDIUM");
  }

  if (/hardcoded|credential|secret/i.test(weaknessClass) || input.cweId === "CWE-798") {
    severity = confidence >= 0.8 ? "CRITICAL" : "HIGH";
  }

  const policySev = (meta.policySeverity as string) || (meta.severity as string);
  if (weaknessClass.toLowerCase().includes("policy") && policySev) {
    severity = parseSeverity(policySev);
  }

  severity = applyCaps(
    severity,
    confidence,
    contextLimited,
    testPath,
    weaknessClass,
    input.cweId,
  );

  const hasStructuredBaseline = Boolean(fromCwe || fromWeakness || fromScanner);
  if (!hasStructuredBaseline) {
    severity = applyCaps(
      llmSeverity,
      confidence,
      contextLimited,
      testPath,
      weaknessClass,
      input.cweId,
    );
  }

  const justification =
    (meta.severityJustification as string)?.trim() ||
    buildJustification({
      severity,
      weaknessClass,
      cweId: input.cweId,
      confidence,
      contextLimited,
      testPath: Boolean(testPath),
      llmSeverity,
      adjusted: llmSeverity !== severity,
    });

  return {
    severity,
    justification,
    llmSeverity,
    adjusted: llmSeverity !== severity,
    weaknessClass,
  };
}

function inferWeaknessClass(input: CalibrateSeverityInput): string {
  const text = `${input.title || ""} ${input.cweId || ""}`.toLowerCase();
  if (input.cweId === "CWE-798" || /hardcoded|secret|credential|api.?key|password|token/i.test(text)) {
    return "Hardcoded Credential";
  }
  if (/command|rce|exec|subprocess|os\.system/i.test(text)) return "Command Injection";
  if (/sql injection|sqli/i.test(text)) return "SQL Injection";
  if (/xss|cross-site/i.test(text)) return "XSS";
  if (/ssrf/i.test(text)) return "SSRF";
  if (/idor|access control|authorization/i.test(text)) return "IDOR";
  if (/path traversal/i.test(text)) return "Path Traversal";
  if (/deserial/i.test(text)) return "Deserialization";
  if (/policy/i.test(text)) return "Policy Violation";
  return "Other";
}

function buildJustification(params: {
  severity: SeverityLevel;
  weaknessClass: string;
  cweId?: string | null;
  confidence: number;
  contextLimited: boolean;
  testPath: boolean;
  llmSeverity: SeverityLevel;
  adjusted: boolean;
}): string {
  const parts = [
    `${params.severity}: ${params.weaknessClass}`,
    params.cweId ? params.cweId : null,
    params.contextLimited ? "exploit path partially confirmed" : "evidence in cited code",
    params.confidence < 0.8 ? `confidence ${params.confidence.toFixed(2)}` : null,
    params.testPath ? "test/fixture path (severity reduced)" : null,
    params.adjusted
      ? `adjusted from model label ${params.llmSeverity}`
      : null,
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
