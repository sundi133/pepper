import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest, NextResponse } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  requireRole: vi.fn(async () => ({ session: {}, membership: { role: "DEVELOPER" } })),
}));
const riskDenied = vi.hoisted(() => vi.fn());
vi.mock("@/lib/permissions", () => ({
  isRiskDecisionStatus: (s: string) => s === "FALSE_POSITIVE" || s === "ACCEPTED_RISK",
  requireRiskDecisionRole: riskDenied,
}));
const db = vi.hoisted(() => ({
  finding: { findFirst: vi.fn(), update: vi.fn(), groupBy: vi.fn(async () => []) },
  scan: { update: vi.fn(async () => ({})) },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
const audit = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: audit, ipFromHeaders: vi.fn(() => "1.2.3.4") }));
vi.mock("@/lib/suppression-rules", () => ({ generateSuppressionRule: vi.fn() }));
vi.mock("@/lib/finding-report", () => ({
  enrichFindingWithReport: (f: unknown) => f,
  findingHasStoredReport: () => true,
}));

import { PATCH } from "./route";

const patch = async (body: unknown) =>
  (await PATCH(
    new NextRequest("http://localhost/api/findings/f1", { method: "PATCH", body: JSON.stringify(body) }),
    { params: Promise.resolve({ findingId: "f1" }) },
  ))!;

beforeEach(() => {
  vi.clearAllMocks();
  riskDenied.mockResolvedValue(null);
});

describe("PATCH /api/findings/[findingId]", () => {
  it("updates the status, audits it and recounts the scan's totals", async () => {
    db.finding.findFirst.mockResolvedValue({ id: "f1", status: "OPEN" });
    db.finding.update.mockResolvedValue({ id: "f1", scanId: "s1", status: "RESOLVED", title: "t", severity: "HIGH" });
    const res = await patch({ status: "RESOLVED", statusNote: "done" });
    expect(res.status).toBe(200);
    expect((await res.json()).status).toBe("RESOLVED");
    expect(db.finding.findFirst.mock.calls[0][0].where).toEqual({ id: "f1", scan: { project: { organizationId: "o1" } } });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "finding.status_changed",
        ipAddress: "1.2.3.4",
        details: { from: "OPEN", to: "RESOLVED", note: "done", title: "t", severity: "HIGH", scanId: "s1" },
      }),
    );
    expect(db.scan.update).toHaveBeenCalledWith(expect.objectContaining({ where: { id: "s1" } }));
  });

  it("404s for a finding outside the organization", async () => {
    db.finding.findFirst.mockResolvedValue(null);
    expect((await patch({ status: "RESOLVED" })).status).toBe(404);
    expect(db.finding.update).not.toHaveBeenCalled();
  });

  it("keeps risk decisions behind the Security role and validates input", async () => {
    riskDenied.mockResolvedValue(NextResponse.json({ error: "no" }, { status: 403 }));
    expect((await patch({ status: "FALSE_POSITIVE" })).status).toBe(403);
    expect((await patch({ status: "BOGUS" })).status).toBe(400);
    expect(db.finding.update).not.toHaveBeenCalled();
  });
});
