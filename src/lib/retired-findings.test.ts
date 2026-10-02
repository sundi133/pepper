import { beforeEach, describe, expect, it, vi } from "vitest";

const findMany = vi.fn();
const updateMany = vi.fn();
const recount = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: { finding: { findMany: (...a: unknown[]) => findMany(...a), updateMany: (...a: unknown[]) => updateMany(...a) } },
}));
vi.mock("@/lib/scan-severity-counts", () => ({ recountScanSeverities: (...a: unknown[]) => recount(...a) }));

import { closeRetiredFindings, RETIRED_NOTE } from "./retired-findings";

beforeEach(() => vi.clearAllMocks());

describe("closeRetiredFindings", () => {
  it("closes open findings of the retired pattern detectors and refreshes their scans", async () => {
    findMany.mockResolvedValue([{ scanId: "s1" }, { scanId: "s2" }]);
    updateMany.mockResolvedValue({ count: 1226 });
    expect(await closeRetiredFindings()).toBe(1226);
    const { where, data } = updateMany.mock.calls[0][0];
    // Open only (existing triage is kept), and only the pattern scanner's findings.
    expect(where.status).toBe("OPEN");
    expect(where.OR).toEqual([
      { scanner: "SECRETS_PATTERN", ruleId: "SECRET-AWS_SECRET_KEY" },
      { scanner: "SECRETS_PATTERN", ruleId: "SECRET-HEROKU_API_KEY" },
    ]);
    expect(data).toMatchObject({ status: "FALSE_POSITIVE", statusNote: RETIRED_NOTE });
    expect(recount.mock.calls.map((c) => c[0])).toEqual(["s1", "s2"]);
  });

  it("does nothing when there are none", async () => {
    findMany.mockResolvedValue([]);
    expect(await closeRetiredFindings()).toBe(0);
    expect(updateMany).not.toHaveBeenCalled();
  });
});
