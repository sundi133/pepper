// CWE → OWASP mapping across three taxonomies:
//   owasp2024 — OWASP Top 10 (web, 2021 categories)
//   owaspApi  — OWASP API Security Top 10 (2023)
//   owaspLlm  — OWASP Top 10 for LLM Applications (2025)
const CWE_TO_OWASP_MAP: Record<string, { owasp2024: string; owaspApi?: string; owaspLlm?: string }> = {
  "CWE-79": { owasp2024: "A03:2021 Injection", owaspLlm: "LLM05:2025 Improper Output Handling" },
  "CWE-89": { owasp2024: "A03:2021 Injection", owaspApi: "A09:2023 Improper Inventory Management" },
  "CWE-90": { owasp2024: "A03:2021 Injection" },
  "CWE-93": { owasp2024: "A03:2021 Injection" },
  "CWE-94": { owasp2024: "A03:2021 Injection", owaspLlm: "LLM01:2025 Prompt Injection" },
  "CWE-95": { owasp2024: "A03:2021 Injection" },
  "CWE-98": { owasp2024: "A03:2021 Injection", owaspLlm: "LLM03:2025 Supply Chain" },
  "CWE-113": { owasp2024: "A03:2021 Injection" },
  "CWE-191": { owasp2024: "A04:2021 Insecure Design" },
  "CWE-200": { owasp2024: "A01:2021 Broken Access Control", owaspLlm: "LLM02:2025 Sensitive Information Disclosure" },
  "CWE-209": { owasp2024: "A09:2021 Security Logging and Monitoring Failures", owaspLlm: "LLM02:2025 Sensitive Information Disclosure" },
  "CWE-215": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-250": { owasp2024: "A01:2021 Broken Access Control", owaspLlm: "LLM06:2025 Excessive Agency" },
  "CWE-269": { owasp2024: "A05:2021 Broken Access Control", owaspLlm: "LLM06:2025 Excessive Agency" },
  "CWE-287": { owasp2024: "A07:2021 Authentication Bypass" },
  "CWE-295": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-296": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-327": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-328": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-331": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-338": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-345": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-347": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-352": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-357": { owasp2024: "A08:2021 Software and Data Integrity Failures" },
  "CWE-359": { owasp2024: "A01:2021 Broken Access Control", owaspLlm: "LLM02:2025 Sensitive Information Disclosure" },
  "CWE-384": { owasp2024: "A07:2021 Identification and Authentication Failures" },
  "CWE-400": { owasp2024: "A05:2021 Security Misconfiguration", owaspLlm: "LLM10:2025 Unbounded Consumption" },
  "CWE-426": { owasp2024: "A08:2021 Software and Data Integrity Failures", owaspApi: "A08:2023 Security Misconfiguration" },
  "CWE-427": { owasp2024: "A08:2021 Software and Data Integrity Failures" },
  "CWE-434": { owasp2024: "A04:2021 Insecure Design" },
  "CWE-470": { owasp2024: "A05:2021 Broken Access Control" },
  "CWE-502": { owasp2024: "A08:2021 Software and Data Integrity Failures", owaspLlm: "LLM04:2025 Data and Model Poisoning" },
  "CWE-522": { owasp2024: "A07:2021 Authentication Bypass" },
  "CWE-525": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-532": { owasp2024: "A09:2021 Security Logging and Monitoring Failures", owaspLlm: "LLM02:2025 Sensitive Information Disclosure" },
  "CWE-611": { owasp2024: "A04:2021 Insecure Design" },
  "CWE-613": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-619": { owasp2024: "A07:2021 Authentication Bypass" },
  "CWE-639": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-643": { owasp2024: "A03:2021 Injection" },
  "CWE-656": { owasp2024: "A05:2021 Broken Access Control" },
  "CWE-665": { owasp2024: "A04:2021 Insecure Design" },
  "CWE-668": { owasp2024: "A05:2021 Broken Access Control" },
  "CWE-672": { owasp2024: "A05:2021 Broken Access Control" },
  "CWE-706": { owasp2024: "A03:2021 Injection" },
  "CWE-732": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-798": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-829": { owasp2024: "A08:2021 Software and Data Integrity Failures", owaspApi: "A08:2023 Security Misconfiguration", owaspLlm: "LLM03:2025 Supply Chain" },
  "CWE-862": { owasp2024: "A01:2021 Broken Access Control", owaspLlm: "LLM06:2025 Excessive Agency" },
  "CWE-863": { owasp2024: "A01:2021 Broken Access Control", owaspApi: "A01:2023 Broken Object Level Authorization", owaspLlm: "LLM06:2025 Excessive Agency" },
  "CWE-915": { owasp2024: "A08:2021 Software and Data Integrity Failures", owaspLlm: "LLM04:2025 Data and Model Poisoning" },
  "CWE-1021": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-1025": { owasp2024: "A08:2021 Software and Data Integrity Failures" },
  "CWE-1104": { owasp2024: "A04:2021 Insecure Design", owaspLlm: "LLM03:2025 Supply Chain" },
  "CWE-1333": { owasp2024: "A04:2021 Insecure Design", owaspLlm: "LLM10:2025 Unbounded Consumption" },
  "CWE-22": { owasp2024: "A01:2021 Broken Access Control", owaspApi: "A01:2023 Broken Object Level Authorization" },
  "CWE-78": { owasp2024: "A03:2021 Injection", owaspLlm: "LLM06:2025 Excessive Agency" },
  "CWE-80": { owasp2024: "A03:2021 Injection" },
  "CWE-116": { owasp2024: "A03:2021 Injection", owaspLlm: "LLM05:2025 Improper Output Handling" },
  "CWE-284": { owasp2024: "A01:2021 Broken Access Control", owaspLlm: "LLM06:2025 Excessive Agency" },
  "CWE-285": { owasp2024: "A01:2021 Broken Access Control", owaspApi: "A01:2023 Broken Object Level Authorization" },
  "CWE-306": { owasp2024: "A07:2021 Identification and Authentication Failures" },
  "CWE-307": { owasp2024: "A07:2021 Identification and Authentication Failures" },
  "CWE-319": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-326": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-601": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-770": { owasp2024: "A05:2021 Security Misconfiguration", owaspLlm: "LLM10:2025 Unbounded Consumption" },
  "CWE-16": { owasp2024: "A05:2021 Security Misconfiguration" },
  "CWE-693": { owasp2024: "A05:2021 Security Misconfiguration" },
  "CWE-918": { owasp2024: "A10:2021 Server-Side Request Forgery (SSRF)", owaspApi: "A07:2023 Server Side Request Forgery" },
  "CWE-1236": { owasp2024: "A03:2021 Injection" },
  "CWE-1427": { owasp2024: "A03:2021 Injection", owaspLlm: "LLM01:2025 Prompt Injection" },
};

// CWE → short human-readable weakness category (for compact UI/PDF labels).
// Single source of truth — do not re-declare this elsewhere.
const CWE_CATEGORY_MAP: Record<string, string> = {
  "CWE-79": "XSS",
  "CWE-80": "XSS",
  "CWE-87": "XSS",
  "CWE-89": "Injection",
  "CWE-90": "Injection",
  "CWE-91": "Injection",
  "CWE-93": "Injection",
  "CWE-94": "Injection",
  "CWE-95": "Injection",
  "CWE-78": "Injection",
  "CWE-77": "Injection",
  "CWE-76": "Injection",
  "CWE-917": "Injection",
  "CWE-22": "Path Traversal",
  "CWE-23": "Path Traversal",
  "CWE-36": "Path Traversal",
  "CWE-73": "Path Traversal",
  "CWE-200": "Info Disclosure",
  "CWE-209": "Info Disclosure",
  "CWE-532": "Info Disclosure",
  "CWE-312": "Secrets",
  "CWE-321": "Secrets",
  "CWE-798": "Secrets",
  "CWE-259": "Secrets",
  "CWE-287": "Authentication",
  "CWE-306": "Authentication",
  "CWE-307": "Authentication",
  "CWE-862": "Authorization",
  "CWE-863": "Authorization",
  "CWE-639": "Authorization",
  "CWE-284": "Authorization",
  "CWE-352": "CSRF",
  "CWE-918": "SSRF",
  "CWE-611": "XXE",
  "CWE-502": "Deserialization",
  "CWE-327": "Cryptography",
  "CWE-328": "Cryptography",
  "CWE-330": "Cryptography",
  "CWE-916": "Cryptography",
  "CWE-1321": "Prototype Pollution",
  "CWE-400": "DoS",
  "CWE-770": "DoS",
  "CWE-16": "Misconfiguration",
  "CWE-693": "Misconfiguration",
  "CWE-1333": "ReDoS",
};

/** Short human-readable weakness category for a CWE (e.g. "Injection"). */
export function getCweCategory(cweId?: string | null): string | null {
  if (!cweId) return null;
  return CWE_CATEGORY_MAP[cweId] || null;
}

/**
 * OWASP Top 10 (2021) code only, e.g. "A03:2021" without the category name.
 * Derived from the authoritative CWE_TO_OWASP_MAP so it never drifts from
 * getOwasp2024Category().
 */
export function getOwasp2024Code(cweId?: string | null): string | null {
  const full = getOwasp2024Category(cweId || undefined);
  return full ? full.split(" ")[0] : null;
}

interface ExploitabilityScore {
  score: number; // 0-10
  attackVector: "network" | "adjacent" | "local" | "physical";
  attackComplexity: "low" | "high";
  privilegesRequired: "none" | "low" | "high";
  userInteraction: "none" | "required";
  scope: "unchanged" | "changed";
}

export function getOwasp2024Category(cweId?: string): string | null {
  if (!cweId) return null;
  const mapping = CWE_TO_OWASP_MAP[cweId];
  return mapping?.owasp2024 || null;
}

export function getOwaspApiCategory(cweId?: string): string | null {
  if (!cweId) return null;
  const mapping = CWE_TO_OWASP_MAP[cweId];
  return mapping?.owaspApi || null;
}

export function getOwaspLlmCategory(cweId?: string): string | null {
  if (!cweId) return null;
  const mapping = CWE_TO_OWASP_MAP[cweId];
  return mapping?.owaspLlm || null;
}

export function calculateExploitabilityScore(
  confidence: number,
  severity: string,
  metadata?: Record<string, unknown>,
): ExploitabilityScore {
  // Base scoring on confidence and severity
  const confidenceWeight = confidence * 10; // 0-10

  const severityWeight = {
    CRITICAL: 9.8,
    HIGH: 8.5,
    MEDIUM: 6.5,
    LOW: 3.5,
    INFO: 0.5,
  }[severity] || 5;

  // Severity-dominant scoring: 70% severity, 30% confidence
  // Prevents low-severity high-confidence findings from inflating exploit score
  const finalScore = (severityWeight * 0.7) + (confidenceWeight * 0.3);

  // Infer attack characteristics from metadata if available
  const route = metadata?.route as string | undefined;
  const sink = metadata?.sink as string | undefined;
  const parameter = metadata?.parameter as string | undefined;

  let attackVector: "network" | "adjacent" | "local" | "physical" = "network";
  let attackComplexity: "low" | "high" = "low";
  let privilegesRequired: "none" | "low" | "high" = "none";
  let userInteraction: "none" | "required" = "none";
  let scope: "unchanged" | "changed" = "unchanged";

  // HTTP endpoints are network-accessible
  if (route && (route.startsWith("http://") || route.includes("/"))) {
    attackVector = "network";
  }

  // Injection and XSS are typically low complexity
  if (sink && /inject|xss|eval|query|exec/i.test(sink)) {
    attackComplexity = "low";
  }

  // Crypto and auth issues might require specific conditions
  if (sink && /crypto|hash|token|password/i.test(sink)) {
    attackComplexity = "high";
    userInteraction = "required";
  }

  // IDOR and authz issues require authentication
  if (/idor|authorization|access control/i.test(metadata?.sink as string || "")) {
    privilegesRequired = "low";
    scope = "changed";
  }

  return {
    score: Math.min(10, Math.max(0.1, finalScore)),
    attackVector,
    attackComplexity,
    privilegesRequired,
    userInteraction,
    scope,
  };
}

export function getExploitabilityLabel(score: number): string {
  if (score >= 9) return "CRITICAL - Easily exploitable";
  if (score >= 8) return "HIGH - Likely exploitable";
  if (score >= 6) return "MEDIUM - May require conditions";
  if (score >= 3) return "LOW - Difficult to exploit";
  return "MINIMAL - Unlikely to exploit";
}
