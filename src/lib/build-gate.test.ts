import { describe, expect, it } from "vitest";
import { evaluateBuildGate } from "./build-gate";

const counts = (c: number, h: number, m = 0, l = 0) => ({ criticalCount: c, highCount: h, mediumCount: m, lowCount: l });

describe("evaluateBuildGate", () => {
  // Customer policy: "Critical > 0, High > 0, build should fail".
  const strict = { maxCritical: 0, maxHigh: 0, maxMedium: -1, maxLow: -1, failOnNew: false };

  it("fails on any critical or high when both thresholds are 0", () => {
    expect(evaluateBuildGate(strict, counts(0, 0, 25, 40), false)).toBe("PASSED");
    expect(evaluateBuildGate(strict, counts(1, 0), false)).toBe("FAILED");
    expect(evaluateBuildGate(strict, counts(0, 1), false)).toBe("FAILED");
  });

  it("treats -1 as disabled and fails only above the threshold", () => {
    const g = { maxCritical: 0, maxHigh: 5, maxMedium: 20, maxLow: -1, failOnNew: false };
    expect(evaluateBuildGate(g, counts(0, 5, 20, 999), false)).toBe("PASSED");
    expect(evaluateBuildGate(g, counts(0, 6), false)).toBe("FAILED");
    expect(evaluateBuildGate(g, counts(0, 0, 21), false)).toBe("FAILED");
  });

  it("fails on new findings only when failOnNew is set", () => {
    const off = { maxCritical: -1, maxHigh: -1, maxMedium: -1, maxLow: -1, failOnNew: false };
    expect(evaluateBuildGate(off, counts(9, 9), true)).toBe("PASSED");
    expect(evaluateBuildGate({ ...off, failOnNew: true }, counts(0, 0), true)).toBe("FAILED");
  });
});
