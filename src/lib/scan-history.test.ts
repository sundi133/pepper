import { describe, expect, it } from "vitest";
import {
  buildRepoSeries,
  fixImpacts,
  repoComparison,
  repoStatePoints,
  type HistoryPoint,
} from "./scan-history";

const NOW = new Date("2026-09-27T12:00:00Z");
const day = (n: number, hour = 10) => new Date(Date.UTC(2026, 8, n, hour));

function pt(d: Date, critical: number, high: number, scanType = "FULL", id = `s${d.getTime()}`): HistoryPoint {
  return { scanId: id, scanType, completedAt: d, commitSha: null, gateResult: "PASSED", critical, high, medium: 0, low: 0, info: 0 };
}

describe("buildRepoSeries", () => {
  it("carries the latest full scan forward and leaves pre-history days empty", () => {
    const series = buildRepoSeries([pt(day(22), 5, 3), pt(day(25), 1, 2)], 7, NOW);
    expect(series.map((s) => s.date)).toEqual([
      "2026-09-21", "2026-09-22", "2026-09-23", "2026-09-24", "2026-09-25", "2026-09-26", "2026-09-27",
    ]);
    expect(series.map((s) => s.critical)).toEqual([null, 5, 5, 5, 1, 1, 1]);
    expect(series.map((s) => s.scans)).toEqual([0, 1, 0, 0, 1, 0, 0]);
  });

  it("starts from the last scan before the window", () => {
    const series = buildRepoSeries([pt(day(1), 9, 9)], 7, NOW);
    expect(series.every((s) => s.critical === 9)).toBe(true);
  });

  it("uses the last full scan of a day and ignores incremental scans", () => {
    const series = buildRepoSeries(
      [pt(day(26, 8), 4, 0), pt(day(26, 20), 2, 0), pt(day(27, 9), 0, 0, "INCREMENTAL")],
      2,
      NOW,
    );
    expect(series.map((s) => s.critical)).toEqual([2, 2]);
  });
});

describe("repoStatePoints", () => {
  it("falls back to non-incremental scans when a repo has no full scans", () => {
    const pts = repoStatePoints([pt(day(20), 1, 0, "SECRETS_ONLY"), pt(day(21), 7, 0, "INCREMENTAL")]);
    expect(pts.map((p) => p.critical)).toEqual([1]);
  });
});

describe("fixImpacts / repoComparison", () => {
  const points = [pt(day(20), 6, 4), pt(day(23), 6, 4), pt(day(26), 1, 2)];
  const run = {
    id: "r1",
    status: "PARTIAL",
    createdAt: day(24, 9),
    completedAt: day(24, 9),
    prUrl: "https://github.com/a/b/pull/7",
    prNumber: 7,
    fixedCount: 5,
    failedCount: 1,
  };

  it("pairs a run with the last scan before and first scan after it", () => {
    const [impact] = fixImpacts([run], points);
    expect(impact.before).toMatchObject({ critical: 6, high: 4 });
    expect(impact.after).toMatchObject({ critical: 1, high: 2 });
    expect(impact.prNumber).toBe(7);
  });

  it("leaves `after` empty until a rescan lands", () => {
    const [impact] = fixImpacts([{ ...run, createdAt: day(26, 12), completedAt: day(26, 12) }], points);
    expect(impact.before).toMatchObject({ critical: 1 });
    expect(impact.after).toBeNull();
  });

  it("compares the state before the first AI fix with the latest scan", () => {
    const cmp = repoComparison(points, fixImpacts([run], points), day(15));
    expect(cmp.baselineLabel).toBe("before_first_fix");
    expect(cmp.baseline).toMatchObject({ critical: 6, high: 4 });
    expect(cmp.current).toMatchObject({ critical: 1, high: 2 });
  });

  it("without fixes, compares against the start of the window", () => {
    const cmp = repoComparison(points, [], day(22));
    expect(cmp.baselineLabel).toBe("window_start");
    expect(cmp.baseline).toMatchObject({ at: day(20).toISOString() });
  });
});

describe("buildOrgSeries", () => {
  it("sums each repository's carried-forward state, even on days it was not scanned", async () => {
    const { buildOrgSeries, seriesComparison } = await import("./scan-history");
    const a = { ...pt(day(24), 4, 0), projectId: "a" };
    const b1 = { ...pt(day(25), 1, 1), projectId: "b" };
    const a2 = { ...pt(day(26), 1, 0), projectId: "a" };
    const series = buildOrgSeries([a, b1, a2], 4, NOW);
    expect(series.map((d) => d.critical)).toEqual([4, 5, 2, 2]);
    expect(series.map((d) => d.scans)).toEqual([1, 1, 1, 0]);
    expect(seriesComparison(series)).toMatchObject({
      baseline: { critical: 4, at: "2026-09-24" },
      current: { critical: 2, at: "2026-09-27" },
    });
  });
});
