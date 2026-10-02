import { describe, expect, it, vi } from "vitest";

const groupBy = vi.fn();
const update = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: {
    finding: { groupBy: (...a: unknown[]) => groupBy(...a) },
    scan: { update: (...a: unknown[]) => update(...a) },
  },
}));

import { recountScanSeverities } from "./scan-severity-counts";

describe("recountScanSeverities", () => {
  it("stores per-severity totals that leave out false positives", async () => {
    groupBy.mockResolvedValue([
      { severity: "CRITICAL", _count: { _all: 2 } },
      { severity: "LOW", _count: { _all: 5 } },
    ]);
    await recountScanSeverities("s1");
    expect(groupBy.mock.calls[0][0].where).toEqual({ scanId: "s1", status: { not: "FALSE_POSITIVE" } });
    expect(update).toHaveBeenCalledWith({
      where: { id: "s1" },
      data: { criticalCount: 2, highCount: 0, mediumCount: 0, lowCount: 5, infoCount: 0 },
    });
  });
});
