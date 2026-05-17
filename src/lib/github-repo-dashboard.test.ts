import { describe, it, expect } from "vitest";
import { deriveRepoScanStatus } from "./github-repo-dashboard";

describe("deriveRepoScanStatus", () => {
  it("returns PENDING when no scan", () => {
    expect(deriveRepoScanStatus(null)).toBe("PENDING");
  });

  it("returns SCANNING when running", () => {
    expect(
      deriveRepoScanStatus({
        status: "RUNNING",
        gateResult: "PENDING",
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        filesScanned: 0,
        completedAt: null,
        createdAt: new Date(),
      }),
    ).toBe("SCANNING");
  });

  it("returns PASSED when completed clean", () => {
    expect(
      deriveRepoScanStatus({
        status: "COMPLETED",
        gateResult: "PASSED",
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        filesScanned: 10,
        completedAt: new Date(),
        createdAt: new Date(),
      }),
    ).toBe("PASSED");
  });

  it("returns ISSUES when critical findings", () => {
    expect(
      deriveRepoScanStatus({
        status: "COMPLETED",
        gateResult: "PASSED",
        criticalCount: 1,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        filesScanned: 10,
        completedAt: new Date(),
        createdAt: new Date(),
      }),
    ).toBe("ISSUES");
  });
});
