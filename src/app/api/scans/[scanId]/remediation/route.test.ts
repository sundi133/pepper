import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  requireRole: vi.fn(),
}));
const runs = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: {
    scan: { findFirst: vi.fn(async () => ({ projectId: "p1" })) },
    remediationRun: { findMany: (...a: unknown[]) => runs(...a) },
  },
}));
vi.mock("@/lib/llm-gateway", () => ({ getLlmConfig: vi.fn() }));
vi.mock("@/lib/queue", () => ({ getRemediationQueue: vi.fn() }));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: vi.fn() }));

import { GET } from "./route";
import { remediationSummary } from "@/components/remediation/remediation-runs-strip";

beforeEach(() => vi.clearAllMocks());

describe("scan remediation runs", () => {
  it("lists this scan's runs and only active runs from the rest of the repository", async () => {
    runs.mockResolvedValue([
      { id: "r1", status: "FAILED", prUrl: null, fixedCount: 1, failedCount: 0, errorMessage: "push rejected", _count: { items: 1 } },
    ]);
    const res = await GET(new NextRequest("http://localhost/api/scans/s2/remediation"), {
      params: Promise.resolve({ scanId: "s2" }),
    });
    expect(runs.mock.calls[0][0].where).toEqual({
      organizationId: "o1",
      OR: [{ scanId: "s2" }, { projectId: "p1", status: { in: ["QUEUED", "RUNNING"] } }],
    });
    expect((await res!.json()).runs).toEqual([
      { id: "r1", status: "FAILED", prUrl: null, fixedCount: 1, failedCount: 0, errorMessage: "push rejected", total: 1 },
    ]);
  });
});

describe("remediationSummary", () => {
  const run = (o: Partial<Parameters<typeof remediationSummary>[0]>) =>
    remediationSummary({ status: "COMPLETED", fixedCount: 1, total: 1, prUrl: null, ...o });

  it("says what failed instead of 'failed — 1/1 fixed'", () => {
    expect(run({ status: "FAILED" })).toBe("AI remediation: 1/1 fixed, pull request not opened");
    expect(run({ status: "FAILED", fixedCount: 0, total: 2 })).toBe("AI remediation failed: no fix was applied");
  });

  it("keeps the other states as they were", () => {
    expect(run({ prUrl: "https://x/pr/1" })).toBe("AI remediation completed — 1/1 fixed");
    expect(run({ status: "PARTIAL", total: 3 })).toBe("AI remediation partially fixed — 1/3 fixed");
    expect(run({ status: "RUNNING" })).toBe("AI remediation running");
    expect(run({ status: "CANCELLED", fixedCount: 0 })).toBe("AI remediation cancelled — 0/1 fixed");
  });
});
