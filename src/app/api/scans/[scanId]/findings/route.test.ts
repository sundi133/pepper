import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
}));
const findMany = vi.fn();
const count = vi.fn();
const groupBy = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: {
    scan: { findFirst: vi.fn(async () => ({ id: "s1" })) },
    finding: {
      findMany: (...a: unknown[]) => findMany(...a),
      count: (...a: unknown[]) => count(...a),
      groupBy: (...a: unknown[]) => groupBy(...a),
      update: vi.fn(),
    },
  },
}));
vi.mock("@/lib/finding-report", () => ({
  enrichFindingWithReport: (f: unknown) => f,
  findingHasStoredReport: () => true,
}));

import { GET } from "./route";

const get = (query = "") =>
  GET(new NextRequest(`http://localhost/api/scans/s1/findings${query}`), { params: Promise.resolve({ scanId: "s1" }) });

beforeEach(() => {
  vi.clearAllMocks();
  findMany.mockResolvedValue([]);
  groupBy.mockResolvedValue([{ scanner: "SAST_LLM", _count: { _all: 4 } }]);
  count.mockImplementation(async ({ where }: { where: { status?: unknown } }) => (where.status === "FALSE_POSITIVE" ? 7 : 4));
});

describe("scan findings API: false positives", () => {
  it("hides false positives by default, in the list, the total and the tab counts", async () => {
    const body = await (await get())!.json();
    const hidden = { not: "FALSE_POSITIVE" };
    expect(findMany.mock.calls[0][0].where.status).toEqual(hidden);
    expect(count.mock.calls[0][0].where.status).toEqual(hidden);
    expect(groupBy.mock.calls[0][0].where.status).toEqual(hidden);
    expect(body.pagination.total).toBe(4);
    expect(body.scannerCounts).toEqual({ SAST_LLM: 4 });
    expect(body.falsePositiveCount).toBe(7);
  });

  it("includes them when asked", async () => {
    await get("?includeFalsePositives=true");
    expect(findMany.mock.calls[0][0].where.status).toBeUndefined();
  });

  it("an explicit status filter returns exactly that status", async () => {
    const body = await (await get("?status=FALSE_POSITIVE"))!.json();
    expect(findMany.mock.calls[0][0].where.status).toEqual({ in: ["FALSE_POSITIVE"] });
    expect(body.falsePositiveCount).toBe(0);
  });
});
