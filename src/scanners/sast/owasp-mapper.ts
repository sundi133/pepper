// OWASP Top 10 2024 + API Security + LLM/AI mapping
const CWE_TO_OWASP_MAP: Record<string, { owasp2024: string; owaspApi?: string; owaspLlm?: string }> = {
  "CWE-79": { owasp2024: "A03:2021 Injection" },
  "CWE-89": { owasp2024: "A03:2021 Injection", owaspApi: "A09:2023 Improper Inventory Management" },
  "CWE-90": { owasp2024: "A03:2021 Injection" },
  "CWE-94": { owasp2024: "A03:2021 Injection", owaspLlm: "A04:2024 Model Poisoning" },
  "CWE-95": { owasp2024: "A03:2021 Injection" },
  "CWE-98": { owasp2024: "A03:2021 Injection", owaspLlm: "A05:2024 Supply Chain Vulnerabilities" },
  "CWE-113": { owasp2024: "A03:2021 Injection" },
  "CWE-191": { owasp2024: "A04:2021 Insecure Design" },
  "CWE-200": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-209": { owasp2024: "A09:2021 Security Logging and Monitoring Failures" },
  "CWE-215": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-269": { owasp2024: "A05:2021 Broken Access Control" },
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
  "CWE-359": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-384": { owasp2024: "A07:2021 Identification and Authentication Failures" },
  "CWE-400": { owasp2024: "A05:2021 Security Misconfiguration" },
  "CWE-426": { owasp2024: "A08:2021 Software and Data Integrity Failures", owaspApi: "A08:2023 Security Misconfiguration" },
  "CWE-427": { owasp2024: "A08:2021 Software and Data Integrity Failures" },
  "CWE-434": { owasp2024: "A04:2021 Insecure Design" },
  "CWE-470": { owasp2024: "A05:2021 Broken Access Control" },
  "CWE-502": { owasp2024: "A08:2021 Software and Data Integrity Failures" },
  "CWE-522": { owasp2024: "A07:2021 Authentication Bypass" },
  "CWE-525": { owasp2024: "A01:2021 Broken Access Control" },
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
  "CWE-829": { owasp2024: "A08:2021 Software and Data Integrity Failures", owaspApi: "A08:2023 Security Misconfiguration" },
  "CWE-862": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-863": { owasp2024: "A01:2021 Broken Access Control", owaspApi: "A01:2023 Broken Object Level Authorization" },
  "CWE-1021": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-1025": { owasp2024: "A08:2021 Software and Data Integrity Failures" },
  "CWE-1104": { owasp2024: "A04:2021 Insecure Design", owaspLlm: "A07:2024 Insecure Output Handling" },
  "CWE-1333": { owasp2024: "A04:2021 Insecure Design" },
  "CWE-22": { owasp2024: "A01:2021 Broken Access Control", owaspApi: "A01:2023 Broken Object Level Authorization" },
  "CWE-78": { owasp2024: "A03:2021 Injection" },
  "CWE-80": { owasp2024: "A03:2021 Injection" },
  "CWE-116": { owasp2024: "A03:2021 Injection" },
  "CWE-284": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-285": { owasp2024: "A01:2021 Broken Access Control", owaspApi: "A01:2023 Broken Object Level Authorization" },
  "CWE-306": { owasp2024: "A07:2021 Identification and Authentication Failures" },
  "CWE-307": { owasp2024: "A07:2021 Identification and Authentication Failures" },
  "CWE-319": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-326": { owasp2024: "A02:2021 Cryptographic Failures" },
  "CWE-601": { owasp2024: "A01:2021 Broken Access Control" },
  "CWE-770": { owasp2024: "A05:2021 Security Misconfiguration" },
  "CWE-918": { owasp2024: "A10:2021 Server-Side Request Forgery (SSRF)", owaspApi: "A07:2023 Server Side Request Forgery" },
  "CWE-1236": { owasp2024: "A03:2021 Injection" },
};

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
