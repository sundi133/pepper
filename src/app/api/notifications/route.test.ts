import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getActiveOrgId: vi.fn(async () => "org1"),
}));

const findMany = vi.fn(async (_args: unknown) => [] as Array<{ id: string }>);
const count = vi.fn(async (_args: unknown) => 0);
const deleteMany = vi.fn(async (_args: unknown) => ({ count: 0 }));
vi.mock("@/lib/prisma", () => ({
  prisma: {
    notification: {
      findMany: (args: unknown) => findMany(args),
      count: (args: unknown) => count(args),
      deleteMany: (args: unknown) => deleteMany(args),
    },
  },
}));

import { DELETE, GET } from "./route";

const row = (id: number) => ({
  id: `n${id}`,
  type: "SCAN_COMPLETED",
  title: "Scan completed",
  body: null,
  read: false,
  scanId: null,
  createdAt: new Date(2026, 0, 1, 0, 0, 100 - id),
});

const responseOf = async (pending: ReturnType<typeof GET> | ReturnType<typeof DELETE>) => {
  const res = await pending;
  if (!res) throw new Error("no response");
  return res;
};

const get = (query = "") =>
  responseOf(GET(new NextRequest(`http://localhost/api/notifications${query}`)));

const del = (query = "") =>
  responseOf(DELETE(new NextRequest(`http://localhost/api/notifications${query}`, { method: "DELETE" })));

beforeEach(() => {
  findMany.mockReset();
  count.mockReset();
  deleteMany.mockReset();
  count.mockResolvedValue(0);
});

describe("GET /api/notifications", () => {
  it("scopes rows to the signed-in user and active org", async () => {
    findMany.mockResolvedValue([]);
    await get();
    expect(findMany.mock.calls[0][0]).toMatchObject({
      where: { userId: "u1", organizationId: "org1" },
    });
  });

  it("returns no nextCursor when the page is not full", async () => {
    findMany.mockResolvedValue([row(1), row(2)]);
    const res = await get("?limit=5");
    const body = await res.json();
    expect(body.notifications).toHaveLength(2);
    expect(body.nextCursor).toBeNull();
  });

  it("fetches one extra row and uses it as the next cursor", async () => {
    findMany.mockResolvedValue([row(1), row(2), row(3)]);
    const res = await get("?limit=2");
    const body = await res.json();
    expect(findMany.mock.calls[0][0]).toMatchObject({ take: 3 });
    expect(body.notifications.map((n: { id: string }) => n.id)).toEqual(["n1", "n2"]);
    expect(body.nextCursor).toBe("n2");
  });

  it("continues from the cursor, skipping the cursor row itself", async () => {
    findMany.mockResolvedValue([]);
    await get("?limit=2&cursor=n2");
    expect(findMany.mock.calls[0][0]).toMatchObject({
      cursor: { id: "n2" },
      skip: 1,
    });
  });

  it("filters to unread rows only when unread=true", async () => {
    findMany.mockResolvedValue([]);
    await get("?unread=true");
    expect(findMany.mock.calls[0][0]).toMatchObject({
      where: { userId: "u1", organizationId: "org1", read: false },
    });
  });

  it("clamps an oversized limit to 100", async () => {
    findMany.mockResolvedValue([]);
    await get("?limit=5000");
    expect(findMany.mock.calls[0][0]).toMatchObject({ take: 101 });
  });

  it("still returns the unread count with the summary", async () => {
    count.mockResolvedValue(7);
    const res = await get("?summary=unread");
    expect(await res.json()).toEqual({ unreadCount: 7 });
  });
});

describe("DELETE /api/notifications?read=true", () => {
  it("deletes only the caller's read notifications and reports the count", async () => {
    deleteMany.mockResolvedValue({ count: 4 });
    const res = await del("?read=true");
    expect(deleteMany.mock.calls[0][0]).toEqual({
      where: { userId: "u1", organizationId: "org1", read: true },
    });
    expect(await res.json()).toEqual({ deleted: 4 });
  });

  it("refuses a bulk delete without read=true", async () => {
    const res = await del();
    expect(res.status).toBe(400);
    expect(deleteMany).not.toHaveBeenCalled();
  });
});
