import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  requireRole: vi.fn(),
}));
const findMany = vi.fn();
const count = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: { scan: { findMany: (...a: unknown[]) => findMany(...a), count: (...a: unknown[]) => count(...a) } },
}));
vi.mock("@/lib/queue", () => ({ scanQueue: { add: vi.fn() } }));
vi.mock("@/lib/minio", () => ({ uploadObject: vi.fn(), ensureBucket: vi.fn() }));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: vi.fn(), ipFromHeaders: vi.fn() }));

import { GET } from "./route";

const get = (query = "") => GET(new NextRequest(`http://localhost/api/scans${query}`));

beforeEach(() => {
  vi.clearAllMocks();
  findMany.mockResolvedValue([]);
  count.mockResolvedValue(0);
});

describe("GET /api/scans search", () => {
  it("lists the organization's scans unfiltered without q", async () => {
    await get();
    expect(findMany.mock.calls[0][0].where).toEqual({ project: { organizationId: "o1" } });
  });

  it("matches repository name, source, branch or scan id, case-insensitively, within the organization", async () => {
    await get("?q=%20wb-red%20&page=2");
    const { where, skip } = findMany.mock.calls[0][0];
    const contains = { contains: "wb-red", mode: "insensitive" };
    expect(where).toEqual({
      project: { organizationId: "o1" },
      OR: [{ project: { name: contains } }, { sourceRef: contains }, { branch: contains }, { id: "wb-red" }],
    });
    expect(count.mock.calls[0][0].where).toEqual(where);
    expect(skip).toBe(20);
  });

  it("ignores a blank query", async () => {
    await get("?q=%20%20");
    expect(findMany.mock.calls[0][0].where.OR).toBeUndefined();
  });
});
