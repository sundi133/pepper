// ─── Risk Score ──────────────────────────────────────────────────────────────
//
// A 0–100 score combining severity, scanner reliability, finding confidence,
// and file-path sensitivity. Lets developers prioritise "top N to fix now"
// without wading through raw severity buckets.
//
// Formula: base × scannerMultiplier × confidenceMultiplier × filePathMultiplier
// Clamped to [1, 100].

// ─── Severity weights ────────────────────────────────────────────────────────

const SEVERITY_BASE: Record<string, number> = {
  CRITICAL: 80,
  HIGH:     55,
  MEDIUM:   30,
  LOW:      12,
  INFO:      3,
};

// ─── Scanner multipliers ─────────────────────────────────────────────────────
// Reflects the typical false-positive rate and exploitability signal per scanner.

const SCANNER_MULTIPLIER: Record<string, number> = {
  MALICIOUS_PKG:   1.15, // explicit supply-chain attack indicators
  SECRETS_PATTERN: 1.10, // credentials are almost always real
  DAST:            1.05, // confirmed by a live HTTP test
  SECRETS_LLM:     1.00,
  SAST_LLM:        0.90,
  IAC:             0.85,
  ZERO_DAY:        0.85, // cross-file AI reasoning is speculative
  SCA:             0.80, // package is vulnerable but reachability unknown
  SAST_PATTERN:    0.75, // pattern-based — highest FP rate
  CONTAINER:       0.75,
};

// ─── File-path sensitivity ───────────────────────────────────────────────────
// Boosts findings in high-value paths; reduces findings in test / doc code.

const SENSITIVE_PATH_PATTERNS = [
  "auth", "login", "oauth", "password", "credential", "token", "session",
  "payment", "billing", "checkout", "stripe", "invoice", "wallet",
  "admin", "superuser", "privilege",
  "crypto", "encrypt", "decrypt", "secret", "key",
];

const LOW_VALUE_PATH_PATTERNS = [
  "test", "spec", "mock", "fixture", "__tests__", ".test.", ".spec.",
  "docs", "example", "sample", "storybook", ".stories.",
];

function filePathMultiplier(filePath: string | null | undefined): number {
  if (!filePath) return 1.0;
  const fp = filePath.toLowerCase();
  if (LOW_VALUE_PATH_PATTERNS.some((p) => fp.includes(p))) return 0.35;
  if (SENSITIVE_PATH_PATTERNS.some((p) => fp.includes(p))) return 1.35;
  return 1.0;
}

// ─── Public API ──────────────────────────────────────────────────────────────

export type RiskScoreInput = {
  severity: string;
  scanner: string;
  confidence?: number | null;
  filePath?: string | null;
  metadata?: Record<string, unknown> | null;
};

/**
 * Compute a risk score in [1, 100].
 *
 * - 80–100 → Critical risk (fix immediately)
 * - 50–79  → High risk
 * - 25–49  → Medium risk
 * - 10–24  → Low risk
 * - 1–9    → Informational / low signal
 */
export function computeRiskScore(finding: RiskScoreInput): number {
  const base = SEVERITY_BASE[finding.severity] ?? 12;
  const scannerMult = SCANNER_MULTIPLIER[finding.scanner] ?? 0.80;
  // If confidence is stored (0–1), use it; otherwise default to 0.75.
  const confidenceMult = finding.confidence != null
    ? Math.max(0.1, finding.confidence)
    : 0.75;
  const pathMult = filePathMultiplier(finding.filePath);

  // EPSS / CISA KEV boost — findings with known exploits or high exploit
  // probability get a risk score bump. Defaults to 1.0 when absent.
  let epssKevMult = 1.0;
  if (finding.metadata) {
    const kevListed = finding.metadata.cisaKevListed as boolean | undefined;
    const epssScore = finding.metadata.epssScore as number | undefined;
    if (kevListed) epssKevMult *= 1.25;
    if (typeof epssScore === "number" && epssScore > 0.1) {
      epssKevMult *= 1.0 + Math.min(epssScore, 0.5);
    }
  }

  const raw = base * scannerMult * confidenceMult * pathMult * epssKevMult;
  return Math.max(1, Math.min(100, Math.round(raw)));
}

export function riskScoreLabel(score: number): "critical" | "high" | "medium" | "low" | "info" {
  if (score >= 75) return "critical";
  if (score >= 48) return "high";
  if (score >= 22) return "medium";
  if (score >= 8)  return "low";
  return "info";
}
