import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest, NextResponse } from "next/server";

let role = "ADMIN";
const RANK: Record<string, number> = { VIEWER: 0, DEVELOPER: 1, SECURITY: 2, ADMIN: 3 };
vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "org1"),
  requireRole: vi.fn(async (_org: string, min: string) =>
    RANK[role] >= RANK[min] ? { session: {}, membership: { role } } : { error: NextResponse.json({ error: "Forbidden" }, { status: 403 }) },
  ),
}));
const upsert = vi.fn();
const auditCreate = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: {
    orgSettings: {
      findUnique: vi.fn(async () => ({ auditLogRetentionDays: null, auditLogArchive: true })),
      upsert: (...a: unknown[]) => upsert(...a),
    },
    auditLog: {
      findFirst: vi.fn(async () => null),
      findMany: vi.fn(async () => []),
      create: (...a: unknown[]) => auditCreate(...a),
    },
    user: { findMany: vi.fn(async () => []) },
    organization: { findUnique: vi.fn(async () => ({ slug: "acme" })) },
  },
}));
vi.mock("@/lib/minio", () => ({ minioClient: {}, BUCKET: "b", uploadObject: vi.fn() }));
vi.mock("@/lib/redis", () => ({ redis: {} }));

import { GET as listAudit } from "./route";
import { GET as exportAudit } from "./export/route";
import { PUT as putRetention } from "./retention/route";

const req = (url: string, body?: unknown) =>
  new NextRequest(`http://localhost${url}`, body === undefined ? {} : { method: "PUT", body: JSON.stringify(body) });

/** Handlers are typed as possibly returning nothing; these always respond. */
async function call(p: Promise<Response | undefined>): Promise<Response> {
  const res = await p;
  if (!res) throw new Error("handler returned no response");
  return res;
}

beforeEach(() => {
  role = "ADMIN";
  vi.clearAllMocks();
});

describe("audit log API", () => {
  it("is limited to security staff and admins", async () => {
    role = "DEVELOPER";
    expect((await call(listAudit(req("/api/audit-log")))).status).toBe(403);
    expect((await call(exportAudit(req("/api/audit-log/export")))).status).toBe(403);
    role = "SECURITY";
    expect((await call(listAudit(req("/api/audit-log")))).status).toBe(200);
  });

  it("rejects bad date filters", async () => {
    const res = await call(listAudit(req("/api/audit-log?from=nope")));
    expect(res.status).toBe(400);
  });

  it("records who exported what", async () => {
    const res = await call(exportAudit(req("/api/audit-log/export?format=csv&from=2026-09-01")));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-disposition")).toMatch(/pepper-audit-log-acme-2026-09-01_to_\d{4}-\d{2}-\d{2}\.csv/);
    expect(auditCreate).toHaveBeenCalledWith(
      expect.objectContaining({ data: expect.objectContaining({ action: "audit.exported", details: expect.objectContaining({ format: "csv" }) }) }),
    );
  });
});

describe("retention settings API", () => {
  it("only admins can change retention", async () => {
    role = "SECURITY";
    expect((await call(putRetention(req("/api/audit-log/retention", { retentionDays: 90 })))).status).toBe(403);
    expect(upsert).not.toHaveBeenCalled();
  });

  it("validates the window", async () => {
    for (const retentionDays of [7, 29, -1, 1.5, "90", 5000]) {
      expect((await call(putRetention(req("/api/audit-log/retention", { retentionDays })))).status).toBe(400);
    }
    expect(upsert).not.toHaveBeenCalled();
  });

  it("saves and audits a change", async () => {
    const res = await call(putRetention(req("/api/audit-log/retention", { retentionDays: 90, archive: false })));
    expect(res.status).toBe(200);
    expect(upsert).toHaveBeenCalledWith(expect.objectContaining({ update: { auditLogRetentionDays: 90, auditLogArchive: false } }));
    expect(auditCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          action: "settings.audit.updated",
          details: { retentionDays: { from: null, to: 90 }, archive: { from: true, to: false } },
        }),
      }),
    );
  });
});
