import { describe, expect, it } from "vitest";
import { canCountResolved, pickBaseline } from "./scan-delta";

const at = (day: number) => new Date(Date.UTC(2026, 8, day, 10));
const snap = (id: string, scanType: string, day: number) => ({ id, scanId: `scan-${id}`, scanType, completedAt: at(day) });

describe("pickBaseline", () => {
  const current = { scanId: "scan-now", scanType: "FULL", createdAt: at(20) };

  it("picks the most recent full scan that finished before this one started", () => {
    const b = pickBaseline([snap("a", "FULL", 10), snap("b", "FULL", 15), snap("c", "INCREMENTAL", 18)], current);
    expect(b?.id).toBe("b");
  });

  it("ignores snapshots from after the scan started and the scan itself", () => {
    const b = pickBaseline(
      [snap("a", "FULL", 10), snap("later", "FULL", 25), { ...snap("self", "FULL", 19), scanId: "scan-now" }],
      current,
    );
    expect(b?.id).toBe("a");
  });

  it("falls back to the same scan type when the repo has no full scans", () => {
    const b = pickBaseline(
      [snap("s1", "SECRETS_ONLY", 12), snap("i1", "INCREMENTAL", 14)],
      { ...current, scanType: "SECRETS_ONLY" },
    );
    expect(b?.id).toBe("s1");
  });

  it("returns null without a usable baseline (behaves like a first scan)", () => {
    expect(pickBaseline([], current)).toBeNull();
    expect(pickBaseline([snap("i1", "INCREMENTAL", 14)], current)).toBeNull();
  });

  it("gives incremental (PR) scans the latest full scan as their baseline", () => {
    const b = pickBaseline([snap("f", "FULL", 10), snap("i", "INCREMENTAL", 15)], { ...current, scanType: "INCREMENTAL" });
    expect(b?.id).toBe("f");
  });
});

describe("canCountResolved", () => {
  it("only counts resolved findings when both scans covered the whole repository", () => {
    expect(canCountResolved("FULL", "FULL")).toBe(true);
    expect(canCountResolved("INCREMENTAL", "FULL")).toBe(false);
    expect(canCountResolved("SECRETS_ONLY", "SECRETS_ONLY")).toBe(false);
    expect(canCountResolved("FULL", "SAST_ONLY")).toBe(false);
  });
});
