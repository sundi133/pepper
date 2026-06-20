import { describe, expect, it } from "vitest";
import { computeRiskScore, riskScoreLabel } from "./risk-score";

describe("computeRiskScore", () => {
  it("returns a number between 1 and 100", () => {
    const cases = [
      { severity: "CRITICAL", scanner: "SECRETS_PATTERN", confidence: 0.95, filePath: "src/auth/login.ts" },
      { severity: "INFO",     scanner: "SAST_PATTERN",    confidence: 0.2,  filePath: "src/__tests__/util.test.ts" },
      { severity: "HIGH",     scanner: "SCA",             confidence: null, filePath: null },
      { severity: "MEDIUM",   scanner: "IAC",             confidence: 0.7,  filePath: "infra/terraform/main.tf" },
    ];
    for (const c of cases) {
      const s = computeRiskScore(c);
      expect(s).toBeGreaterThanOrEqual(1);
      expect(s).toBeLessThanOrEqual(100);
    }
  });

  it("scores CRITICAL higher than HIGH for the same scanner", () => {
    const critical = computeRiskScore({ severity: "CRITICAL", scanner: "SAST_LLM", confidence: 0.8, filePath: "src/app.ts" });
    const high     = computeRiskScore({ severity: "HIGH",     scanner: "SAST_LLM", confidence: 0.8, filePath: "src/app.ts" });
    expect(critical).toBeGreaterThan(high);
  });

  it("boosts secrets scanner over pattern SAST for same severity", () => {
    const secret  = computeRiskScore({ severity: "HIGH", scanner: "SECRETS_PATTERN", confidence: 0.8, filePath: "src/config.ts" });
    const pattern = computeRiskScore({ severity: "HIGH", scanner: "SAST_PATTERN",    confidence: 0.8, filePath: "src/config.ts" });
    expect(secret).toBeGreaterThan(pattern);
  });

  it("penalises test file paths", () => {
    const prod = computeRiskScore({ severity: "HIGH", scanner: "SAST_LLM", confidence: 0.8, filePath: "src/auth/session.ts" });
    const test = computeRiskScore({ severity: "HIGH", scanner: "SAST_LLM", confidence: 0.8, filePath: "src/__tests__/session.test.ts" });
    expect(prod).toBeGreaterThan(test);
  });

  it("boosts sensitive auth file paths", () => {
    const auth    = computeRiskScore({ severity: "HIGH", scanner: "SAST_LLM", confidence: 0.8, filePath: "src/auth/oauth.ts" });
    const neutral = computeRiskScore({ severity: "HIGH", scanner: "SAST_LLM", confidence: 0.8, filePath: "src/utils/format.ts" });
    expect(auth).toBeGreaterThan(neutral);
  });

  it("boosts payment paths", () => {
    const payment = computeRiskScore({ severity: "HIGH", scanner: "SAST_LLM", confidence: 0.8, filePath: "src/billing/checkout.ts" });
    const neutral = computeRiskScore({ severity: "HIGH", scanner: "SAST_LLM", confidence: 0.8, filePath: "src/utils/format.ts" });
    expect(payment).toBeGreaterThan(neutral);
  });

  it("uses default confidence of 0.75 when confidence is null", () => {
    const withDefault  = computeRiskScore({ severity: "HIGH", scanner: "SAST_LLM", confidence: null,  filePath: null });
    const explicit75   = computeRiskScore({ severity: "HIGH", scanner: "SAST_LLM", confidence: 0.75,  filePath: null });
    expect(withDefault).toBe(explicit75);
  });

  it("handles missing/unknown severity gracefully", () => {
    const s = computeRiskScore({ severity: "UNKNOWN", scanner: "SAST_LLM", confidence: 0.8, filePath: null });
    expect(s).toBeGreaterThanOrEqual(1);
  });

  it("handles null filePath gracefully", () => {
    const s = computeRiskScore({ severity: "HIGH", scanner: "SAST_LLM", confidence: 0.8, filePath: null });
    expect(s).toBeGreaterThanOrEqual(1);
    expect(s).toBeLessThanOrEqual(100);
  });
});

describe("riskScoreLabel", () => {
  it("labels 80+ as critical", () => {
    expect(riskScoreLabel(80)).toBe("critical");
    expect(riskScoreLabel(100)).toBe("critical");
  });

  it("labels 48–74 as high", () => {
    expect(riskScoreLabel(48)).toBe("high");
    expect(riskScoreLabel(74)).toBe("high");
  });

  it("labels 22–47 as medium", () => {
    expect(riskScoreLabel(22)).toBe("medium");
    expect(riskScoreLabel(47)).toBe("medium");
  });

  it("labels 8–21 as low", () => {
    expect(riskScoreLabel(8)).toBe("low");
    expect(riskScoreLabel(21)).toBe("low");
  });

  it("labels below 8 as info", () => {
    expect(riskScoreLabel(1)).toBe("info");
    expect(riskScoreLabel(7)).toBe("info");
  });
});
