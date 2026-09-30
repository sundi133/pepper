import { describe, expect, it, vi } from "vitest";

const rows = Array.from({ length: 2500 }, (_, i) => ({
  id: `a${String(2500 - i).padStart(5, "0")}`,
  organizationId: "org1",
  userId: i % 2 ? "u1" : null,
  action: "user.login",
  resource: "user",
  resourceId: null,
  details: i === 0 ? { note: 'says "hi", =cmd' } : null,
  ipAddress: "10.0.0.1",
  createdAt: new Date(Date.UTC(2026, 8, 1) - i * 1000),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: {
    auditLog: {
      findMany: vi.fn(async ({ take, cursor }: { take: number; cursor?: { id: string } }) => {
        const start = cursor ? rows.findIndex((r) => r.id === cursor.id) + 1 : 0;
        return rows.slice(start, start + take);
      }),
    },
    user: {
      findMany: vi.fn(async () => [{ id: "u1", email: "=ann@acme.test", name: "Ann" }]),
    },
  },
}));

import { auditRows, csvCell, exportStream, parseAuditFilters } from "./audit-export";

async function readAll(stream: ReadableStream<Uint8Array>): Promise<string> {
  return new Response(stream).text();
}

describe("parseAuditFilters", () => {
  it("treats a date-only 'to' as the whole day", () => {
    const r = parseAuditFilters(new URLSearchParams("from=2026-09-01&to=2026-09-30&action=user.login"));
    expect(r).toEqual({
      filters: {
        action: "user.login",
        from: new Date("2026-09-01T00:00:00.000Z"),
        to: new Date("2026-09-30T23:59:59.999Z"),
      },
    });
  });

  it("rejects bad dates and inverted ranges", () => {
    expect(parseAuditFilters(new URLSearchParams("from=yesterday"))).toEqual({ error: 'Invalid "from" date: yesterday' });
    expect(parseAuditFilters(new URLSearchParams("from=2026-10-01&to=2026-09-01"))).toEqual({ error: '"from" is after "to"' });
  });
});

describe("csvCell", () => {
  it("quotes and neutralises spreadsheet formulas", () => {
    expect(csvCell("plain")).toBe("plain");
    expect(csvCell('a "b", c')).toBe('"a ""b"", c"');
    expect(csvCell("=HYPERLINK(1)")).toBe("'=HYPERLINK(1)");
    expect(csvCell("@SUM(A1)")).toBe("'@SUM(A1)");
    expect(csvCell({ a: 1 })).toBe('"{""a"":1}"');
    expect(csvCell(null)).toBe("");
  });
});

describe("export", () => {
  it("pages through every entry, newest first, with user details", async () => {
    const out = [];
    for await (const r of auditRows("org1", {})) out.push(r);
    expect(out).toHaveLength(2500);
    expect(new Set(out.map((r) => r.id)).size).toBe(2500);
    expect(out[1].user).toEqual({ id: "u1", email: "=ann@acme.test", name: "Ann" });
  });

  it("streams valid CSV", async () => {
    const csv = await readAll(exportStream("csv", auditRows("org1", {})));
    const lines = csv.trimEnd().split("\r\n");
    expect(lines[0]).toBe("timestamp,action,resource,resourceId,userId,userEmail,userName,ipAddress,details");
    expect(lines).toHaveLength(2501);
    expect(lines[1]).toBe(`2026-09-01T00:00:00.000Z,user.login,user,,,,,10.0.0.1,"{""note"":""says \\""hi\\"", =cmd""}"`);
    expect(lines[2]).toContain(",u1,'=ann@acme.test,Ann,");
  });

  it("streams a valid JSON array", async () => {
    const json = JSON.parse(await readAll(exportStream("json", auditRows("org1", {}))));
    expect(json).toHaveLength(2500);
    expect(json[1]).toMatchObject({ action: "user.login", user: { id: "u1", email: "=ann@acme.test" }, ipAddress: "10.0.0.1" });
    const empty = JSON.parse(await readAll(exportStream("json", (async function* () {})())));
    expect(empty).toEqual([]);
  });
});
