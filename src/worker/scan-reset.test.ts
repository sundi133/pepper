import { beforeEach, describe, expect, it, vi } from "vitest";

const db = {
  findings: [] as Array<{ id: string; scanId: string }>,
  artifacts: [] as Array<{ scanId: string }>,
  scans: [] as Array<Record<string, unknown> & { id: string }>,
};
vi.mock("@/lib/prisma", () => ({
  prisma: {
    $transaction: vi.fn(async (ops: Array<Promise<unknown>>) => Promise.all(ops)),
    finding: {
      deleteMany: vi.fn(async ({ where }: { where: { scanId: string } }) => {
        const before = db.findings.length;
        db.findings = db.findings.filter((f) => f.scanId !== where.scanId);
        return { count: before - db.findings.length };
      }),
    },
    scanArtifact: {
      deleteMany: vi.fn(async ({ where }: { where: { scanId: string } }) => {
        db.artifacts = db.artifacts.filter((a) => a.scanId !== where.scanId);
        return { count: 0 };
      }),
    },
    scan: {
      update: vi.fn(async ({ where, data }: { where: { id: string }; data: Record<string, unknown> }) =>
        Object.assign(db.scans.find((s) => s.id === where.id)!, data),
      ),
    },
  },
}));

import { clearPreviousAttempt } from "./scan-reset";

beforeEach(() => {
  db.findings = [];
  db.artifacts = [];
  db.scans = [{ id: "s1", criticalCount: 10, highCount: 7, gateResult: "FAILED", status: "RUNNING" }];
});

describe("clearPreviousAttempt", () => {
  it("removes an interrupted attempt's findings and totals so a re-run can't double them", async () => {
    db.findings = [
      { id: "a", scanId: "s1" },
      { id: "b", scanId: "s1" },
      { id: "other", scanId: "s2" },
    ];
    db.artifacts = [{ scanId: "s1" }, { scanId: "s2" }];
    await expect(clearPreviousAttempt("s1")).resolves.toBe(2);
    expect(db.findings).toEqual([{ id: "other", scanId: "s2" }]);
    expect(db.artifacts).toEqual([{ scanId: "s2" }]);
    expect(db.scans[0]).toMatchObject({ criticalCount: 0, highCount: 0, gateResult: "PENDING", status: "RUNNING" });
  });

  it("is a no-op on a normal first start", async () => {
    await expect(clearPreviousAttempt("s1")).resolves.toBe(0);
  });
});
