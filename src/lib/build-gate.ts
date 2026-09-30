/**
 * Build-gate decision. A threshold of -1 disables that severity; otherwise
 * the gate fails when the count is ABOVE the threshold (so 0 means "any
 * finding of this severity fails"). All checks are OR'ed.
 */
export interface BuildGateRules {
  maxCritical: number;
  maxHigh: number;
  maxMedium: number;
  maxLow: number;
  failOnNew: boolean;
}

export interface SeverityCounts {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

export function evaluateBuildGate(
  gate: BuildGateRules,
  counts: SeverityCounts,
  hasNewFindings: boolean,
): "PASSED" | "FAILED" {
  const over = (max: number, n: number) => max >= 0 && n > max;
  const failed =
    (gate.failOnNew && hasNewFindings) ||
    over(gate.maxCritical, counts.criticalCount) ||
    over(gate.maxHigh, counts.highCount) ||
    over(gate.maxMedium, counts.mediumCount) ||
    over(gate.maxLow, counts.lowCount);
  return failed ? "FAILED" : "PASSED";
}
