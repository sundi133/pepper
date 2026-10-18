import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest, NextResponse } from "next/server";

const requireRole = vi.fn();
vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  requireRole: (...a: unknown[]) => requireRole(...a),
}));
const db = {
  findMany: vi.fn(),
  findFirst: vi.fn(),
  create: vi.fn(),
  update: vi.fn(),
  deleteMany: vi.fn(),
};
vi.mock("@/lib/prisma", () => ({
  prisma: {
    reportTemplate: {
      findMany: (...a: unknown[]) => db.findMany(...a),
      findFirst: (...a: unknown[]) => db.findFirst(...a),
      create: (...a: unknown[]) => db.create(...a),
      update: (...a: unknown[]) => db.update(...a),
      deleteMany: (...a: unknown[]) => db.deleteMany(...a),
    },
  },
}));
const audit = vi.fn();
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: (...a: unknown[]) => audit(...a), ipFromHeaders: vi.fn(() => null) }));

import * as list from "./route";
import * as one from "./[templateId]/route";
import * as preview from "./preview/route";

/** Handlers always respond; drop the `undefined` their inferred types allow. */
type Responds<F> = F extends (...a: infer A) => Promise<infer R> ? (...a: A) => Promise<NonNullable<R>> : never;
const GET = list.GET as Responds<typeof list.GET>;
const POST = list.POST as Responds<typeof list.POST>;
const GET_ONE = one.GET as Responds<typeof one.GET>;
const PATCH = one.PATCH as Responds<typeof one.PATCH>;
const DELETE = one.DELETE as Responds<typeof one.DELETE>;
const PREVIEW = preview.POST as Responds<typeof preview.POST>;

const forbidden = () => ({ error: NextResponse.json({ error: "Forbidden" }, { status: 403 }) });
const json = (url: string, method: string, body: unknown) =>
  new NextRequest(`http://localhost${url}`, { method, body: JSON.stringify(body) });
const idParams = { params: Promise.resolve({ templateId: "t1" }) };
const VALID = { name: "Monthly", format: "markdown", body: "## Summary\nWrite it.", instructions: "For the CTO" };

beforeEach(() => {
  vi.clearAllMocks();
  requireRole.mockResolvedValue({ session: {}, membership: { role: "SECURITY" } });
  db.findMany.mockResolvedValue([{ id: "t1", name: "Monthly" }]);
  db.findFirst.mockResolvedValue({ id: "t1", format: "markdown", body: "## A\nx" });
  db.create.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ id: "t1", ...data }));
  db.update.mockImplementation(async ({ data }: { data: Record<string, unknown> }) => ({ id: "t1", name: "Monthly", ...data }));
  db.deleteMany.mockResolvedValue({ count: 1 });
});

describe("report template API", () => {
  it("lists only the caller's organization's templates", async () => {
    const res = await GET();
    expect(res.status).toBe(200);
    expect(db.findMany.mock.calls[0][0].where).toEqual({ organizationId: "o1" });
    expect((await res.json()).templates).toHaveLength(1);
  });

  it("creates a template in the caller's organization and audit-logs it", async () => {
    const res = await POST(json("/api/settings/report-templates", "POST", VALID));
    expect(res.status).toBe(201);
    expect(requireRole).toHaveBeenCalledWith("o1", "SECURITY");
    expect(db.create.mock.calls[0][0].data).toMatchObject({ organizationId: "o1", name: "Monthly", createdBy: "u1", instructions: "For the CTO" });
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({ action: "report_template.created", resource: "report_template" }));
  });

  it("refuses changes from developers and viewers", async () => {
    requireRole.mockResolvedValue(forbidden());
    expect((await POST(json("/api/settings/report-templates", "POST", VALID))).status).toBe(403);
    expect((await PATCH(json("/api/settings/report-templates/t1", "PATCH", { name: "x" }), idParams)).status).toBe(403);
    expect((await DELETE(new NextRequest("http://localhost/x", { method: "DELETE" }), idParams)).status).toBe(403);
    expect(db.create).not.toHaveBeenCalled();
    expect(db.update).not.toHaveBeenCalled();
    expect(db.deleteMany).not.toHaveBeenCalled();
  });

  it("validates name, format, size and content", async () => {
    const post = (b: unknown) => POST(json("/api/settings/report-templates", "POST", b));
    expect((await post({ ...VALID, name: "  " })).status).toBe(400);
    expect((await post({ ...VALID, format: "pdf" })).status).toBe(400);
    expect((await post({ ...VALID, body: "x".repeat(100_001) })).status).toBe(400);
    expect((await post({ ...VALID, format: "html", body: "<script>alert(1)</script>" })).status).toBe(400);
    expect((await post("not json")).status).toBe(400);
    expect(db.create).not.toHaveBeenCalled();
  });

  it("reports a duplicate name as a conflict", async () => {
    db.create.mockRejectedValue(Object.assign(new Error("unique"), { code: "P2002" }));
    expect((await POST(json("/api/settings/report-templates", "POST", VALID))).status).toBe(409);
  });

  it("scopes reads, edits and deletes to the caller's organization", async () => {
    db.findFirst.mockResolvedValue(null);
    expect((await GET_ONE(new NextRequest("http://localhost/x"), idParams)).status).toBe(404);
    expect((await PATCH(json("/x", "PATCH", { name: "y" }), idParams)).status).toBe(404);
    expect(db.findFirst.mock.calls[0][0].where).toEqual({ id: "t1", organizationId: "o1" });
    expect(db.update).not.toHaveBeenCalled();

    db.deleteMany.mockResolvedValue({ count: 0 });
    expect((await DELETE(new NextRequest("http://localhost/x", { method: "DELETE" }), idParams)).status).toBe(404);
    expect(db.deleteMany.mock.calls[0][0].where).toEqual({ id: "t1", organizationId: "o1" });
  });

  it("updates only the fields sent (format is not reset)", async () => {
    const res = await PATCH(json("/x", "PATCH", { name: "Renamed" }), idParams);
    expect(res.status).toBe(200);
    expect(db.update.mock.calls[0][0].data).toEqual({ name: "Renamed" });
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({ action: "report_template.updated" }));
  });

  it("previews sections, placeholders and a sanitized rendering", async () => {
    requireRole.mockResolvedValue({ session: {}, membership: { role: "VIEWER" } });
    const res = await PREVIEW(
      json("/x", "POST", {
        format: "html",
        body: "<h1>Report</h1><h2>Summary</h2><p>{{findings.critical_count}} {{bogus.value}}</p><img src=x onerror=alert(1)>",
      }),
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.title).toBe("Report");
    expect(body.sections.map((s: { heading: string }) => s.heading)).toEqual(["Summary"]);
    expect(body.placeholders).toEqual({ known: ["findings.critical_count"], unknown: ["bogus.value"] });
    expect(body.html).toContain("<code>{{findings.critical_count}}</code>");
    expect(body.html).not.toMatch(/onerror|<img/);
  });
});
