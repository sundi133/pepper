import { describe, it, expect } from "vitest";
import { enhanceSCAFindingWithRiskScore } from "./supply-chain-scorer";
import type { RawFinding } from "../types";
import type { SupplyChainRiskScore } from "./supply-chain-scorer";

function finding(
  metadata: Record<string, unknown> = {},
  severity: RawFinding["severity"] = "HIGH",
): RawFinding {
  return {
    scanner: "SCA",
    severity,
    title: "CVE-2024-0001: something bad",
    description: "advisory text",
    confidence: 1.0,
    metadata: {
      packageName: "left-pad",
      packageVersion: "1.3.0",
      ecosystem: "npm",
      ...metadata,
    },
  };
}

function score(f: RawFinding, direct: string[] = []): SupplyChainRiskScore {
  const enhanced = enhanceSCAFindingWithRiskScore(f, new Set(direct));
  return enhanced.metadata!.supplyChainRisk as SupplyChainRiskScore;
}

describe("supply chain risk scoring — exploitability", () => {
  it("reports unknown exploitability when no EPSS/KEV data is present", () => {
    // Regression: exploitability used to be derived from `confidence`, which is
    // always 1.0 for OSV findings, so every finding scored "high".
    const s = score(finding());
    expect(s.vulnerability.exploitability).toBe("unknown");
    expect(s.knownExploited).toBe(false);
    expect(s.vulnerability.epssScore).toBeUndefined();
  });

  it("does not treat missing EPSS/KEV data as high exploitability", () => {
    const withoutData = score(finding({ confidence: 1.0 }));
    const withLowEpss = score(finding({ epssScore: 0.0001 }));
    expect(withoutData.vulnerability.exploitability).not.toBe("high");
    expect(withLowEpss.vulnerability.exploitability).toBe("low");
  });

  it("maps EPSS scores to exploitability bands", () => {
    expect(score(finding({ epssScore: 0.5 })).vulnerability.exploitability).toBe(
      "high",
    );
    expect(score(finding({ epssScore: 0.1 })).vulnerability.exploitability).toBe(
      "high",
    );
    expect(
      score(finding({ epssScore: 0.05 })).vulnerability.exploitability,
    ).toBe("medium");
    expect(
      score(finding({ epssScore: 0.0005 })).vulnerability.exploitability,
    ).toBe("low");
  });

  it("treats CISA KEV listing as high exploitability regardless of EPSS", () => {
    const s = score(finding({ epssScore: 0.0001, cisaKevListed: true }));
    expect(s.vulnerability.exploitability).toBe("high");
    expect(s.knownExploited).toBe(true);
  });

  it("scores a KEV-listed vulnerability above an identical non-KEV one", () => {
    const base = score(finding({ epssScore: 0.0001 }));
    const kev = score(finding({ epssScore: 0.0001, cisaKevListed: true }));
    expect(kev.riskScore).toBeGreaterThan(base.riskScore);
  });

  it("exposes the EPSS score for downstream triage and UI", () => {
    expect(score(finding({ epssScore: 0.42 })).vulnerability.epssScore).toBe(
      0.42,
    );
  });

  it("ignores a non-numeric EPSS score rather than throwing", () => {
    const s = score(finding({ epssScore: "not-a-number" }));
    expect(s.vulnerability.exploitability).toBe("unknown");
  });

  it("still ranks direct dependencies above deep transitive ones", () => {
    const direct = score(finding({ epssScore: 0.5 }), ["left-pad"]);
    const transitive = score(finding({ epssScore: 0.5 }));
    expect(direct.directDependency).toBe(true);
    expect(direct.transitiveSeverity).toBe("immediate");
    expect(transitive.transitiveSeverity).toBe("deep");
    expect(direct.riskScore).toBeGreaterThan(transitive.riskScore);
  });

  it("clamps the score to 0-100", () => {
    const s = score(
      finding({ epssScore: 0.99, cisaKevListed: true }, "CRITICAL"),
      ["left-pad"],
    );
    expect(s.riskScore).toBeLessThanOrEqual(100);
    expect(s.riskScore).toBeGreaterThanOrEqual(0);
  });
});
