import { RawFinding } from "../types";

export interface SupplyChainRiskScore {
  riskScore: number; // 0-100
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  directDependency: boolean;
  transitiveSeverity: "immediate" | "indirect" | "deep";
  hasFixAvailable: boolean;
  isWidelyUsed: boolean;
  /** True when CISA lists this CVE as exploited in the wild. */
  knownExploited: boolean;
  vulnerability: {
    baseScore: number;
    /** Derived from EPSS/KEV; "unknown" when neither feed returned data. */
    exploitability: "high" | "medium" | "low" | "unknown";
    /** EPSS probability of exploitation in the next 30 days, when available. */
    epssScore?: number;
  };
}

/**
 * EPSS thresholds. 0.1 (10% chance of exploitation within 30 days) is the
 * commonly used "prioritize now" cut-off; below 0.001 is effectively noise.
 */
const EPSS_HIGH_THRESHOLD = 0.1;
const EPSS_MEDIUM_THRESHOLD = 0.01;

/**
 * Exploitability from real exploitation signals.
 *
 * Previously this was derived from `finding.confidence`, but OSV-sourced SCA
 * findings are always confidence 1.0, so every finding scored "high" and the
 * multiplier was inert. EPSS/KEV are fetched upstream in sca/index.ts.
 */
function deriveExploitability(
  epssScore: number | undefined,
  knownExploited: boolean,
): "high" | "medium" | "low" | "unknown" {
  // Confirmed exploited in the wild outranks any prediction.
  if (knownExploited) return "high";
  if (typeof epssScore !== "number" || Number.isNaN(epssScore)) return "unknown";
  if (epssScore >= EPSS_HIGH_THRESHOLD) return "high";
  if (epssScore >= EPSS_MEDIUM_THRESHOLD) return "medium";
  return "low";
}

function scoreSupplyChainRisk(
  finding: RawFinding,
  directDependencies: Set<string>,
): SupplyChainRiskScore {
  const metadata = finding.metadata as Record<string, unknown>;
  const packageName = metadata?.packageName as string | undefined;
  const fixVersion = metadata?.fixVersion as string | undefined;
  const usageLocations = metadata?.usageLocations as
    | Array<{ filePath: string }>
    | undefined;

  const isDirectDependency = packageName ? directDependencies.has(packageName) : false;

  // Determine transitivity severity
  let transitiveSeverity: "immediate" | "indirect" | "deep" = "indirect";
  if (isDirectDependency) {
    transitiveSeverity = "immediate";
  } else if (usageLocations && usageLocations.length > 0) {
    // If we can find usage in code, it's at least being used somewhere
    transitiveSeverity = "indirect";
  } else {
    // Deep transitive dependency with no visible usage
    transitiveSeverity = "deep";
  }

  // Calculate base score from severity
  const severityScores = {
    CRITICAL: 9.5,
    HIGH: 7.5,
    MEDIUM: 5.0,
    LOW: 2.0,
    INFO: 0.5,
  };
  const baseScore = severityScores[finding.severity as keyof typeof severityScores] || 5.0;

  // Determine exploitability from EPSS / CISA KEV (set by epss-kev-enrichment).
  const epssScore =
    typeof metadata?.epssScore === "number"
      ? (metadata.epssScore as number)
      : undefined;
  const knownExploited = metadata?.cisaKevListed === true;
  const exploitability = deriveExploitability(epssScore, knownExploited);

  // Check if fix is available
  const hasFixAvailable = !!fixVersion;

  // Estimate if package is widely used (heuristic: common packages)
  const commonPackages = new Set([
    "lodash",
    "react",
    "vue",
    "angular",
    "express",
    "next",
    "axios",
    "moment",
    "date-fns",
    "webpack",
    "babel",
    "typescript",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "chai",
    "sinon",
    "underscore",
    "jquery",
    "bootstrap",
    "d3",
    "three",
    "tensorflow",
    "pytorch",
    "numpy",
    "scipy",
    "pandas",
    "flask",
    "django",
    "requests",
    "click",
    "cryptography",
    "requests-oauthlib",
    "jinja2",
    "werkzeug",
    "sqlalchemy",
    "psycopg2",
    "pymongo",
    "redis",
    "elasticsearch",
    "grpc",
    "protobuf",
    "jsonschema",
    "pyyaml",
    "pillow",
    "scipy",
    "scikit-learn",
    "matplotlib",
    "seaborn",
  ]);
  const isWidelyUsed = packageName ? commonPackages.has(packageName.toLowerCase()) : false;

  // Calculate final risk score
  let riskScore = baseScore * 10; // Start with severity (0-95)

  // Adjust for directness (direct deps are more critical)
  if (isDirectDependency) {
    riskScore *= 1.2; // 20% increase for direct deps
  } else if (transitiveSeverity === "deep") {
    riskScore *= 0.7; // 30% decrease for deep transitive
  }

  // Adjust for exploitability. "unknown" is neutral — absent EPSS/KEV data must
  // not be read as low risk.
  if (exploitability === "high") {
    riskScore *= 1.1;
  } else if (exploitability === "low") {
    riskScore *= 0.8;
  }

  // Confirmed exploited in the wild is the strongest signal available and
  // should dominate the heuristic multipliers below.
  if (knownExploited) {
    riskScore *= 1.25;
  }

  // Reduce risk if fix is available
  if (hasFixAvailable) {
    riskScore *= 0.85; // 15% reduction if fix available
  } else {
    riskScore *= 1.15; // 15% increase if no fix
  }

  // Adjust for widely-used packages (they get more scrutiny)
  if (isWidelyUsed) {
    riskScore *= 0.9; // 10% reduction for widely-used (community-vetted)
  }

  // Clamp to 0-100
  riskScore = Math.min(100, Math.max(0, riskScore));

  // Determine risk level
  let riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  if (riskScore >= 85) riskLevel = "CRITICAL";
  else if (riskScore >= 65) riskLevel = "HIGH";
  else if (riskScore >= 40) riskLevel = "MEDIUM";
  else riskLevel = "LOW";

  return {
    riskScore: Math.round(riskScore),
    riskLevel,
    directDependency: isDirectDependency,
    transitiveSeverity,
    hasFixAvailable,
    isWidelyUsed,
    knownExploited,
    vulnerability: {
      baseScore,
      exploitability,
      ...(epssScore !== undefined ? { epssScore } : {}),
    },
  };
}

export function enhanceSCAFindingWithRiskScore(
  finding: RawFinding,
  directDependencies: Set<string>,
): RawFinding {
  const riskScore = scoreSupplyChainRisk(finding, directDependencies);

  return {
    ...finding,
    metadata: {
      ...finding.metadata,
      supplyChainRisk: riskScore,
    },
  };
}

