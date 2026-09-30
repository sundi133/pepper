import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  requireRole: vi.fn(async () => ({ session: {}, membership: { role: "DEVELOPER" } })),
}));
const scan = { id: "s1", branch: "main", project: { id: "p1", name: "app", organizationId: "o1", azureProjectName: null } };
const findingRows = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: {
    scan: { findFirst: vi.fn(async () => scan) },
    finding: { findMany: (...a: unknown[]) => findingRows(...a) },
  },
}));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: vi.fn(async () => undefined), ipFromHeaders: vi.fn(() => null) }));
const load = vi.fn();
const raise = vi.fn();
vi.mock("@/lib/integrations/bulk-tickets", () => ({
  BULK_TICKET_LIMIT: 3,
  TICKET_KIND_LABELS: { AZURE_BOARDS: "Azure Boards", JIRA: "Jira" },
  loadTicketIntegrations: (...a: unknown[]) => load(...a),
  raiseTicketsForFindings: (...a: unknown[]) => raise(...a),
}));

import { GET, POST } from "./route";

const params = { params: Promise.resolve({ scanId: "s1" }) };
const post = (body: unknown) =>
  POST(new NextRequest("http://localhost/api/scans/s1/tickets", { method: "POST", body: JSON.stringify(body) }), params);

beforeEach(() => {
  vi.clearAllMocks();
  load.mockResolvedValue([{ id: "b1", name: "Azure Boards (poc2)", kind: "AZURE_BOARDS", config: { organization: "x", pat: "secret" } }]);
  findingRows.mockResolvedValue([{ id: "f1", title: "SQLi" }]);
  raise.mockResolvedValue([{ integrationId: "b1", name: "Azure Boards (poc2)", created: 1, existing: 0, tickets: [], failed: [] }]);
});

describe("scan tickets API", () => {
  it("lists ticket systems without their secrets", async () => {
    const res = await GET(new NextRequest("http://localhost/api/scans/s1/tickets"), params);
    const body = await res!.json();
    expect(body.targets).toEqual([{ id: "b1", name: "Azure Boards (poc2)", kind: "AZURE_BOARDS", kindLabel: "Azure Boards" }]);
    expect(JSON.stringify(body)).not.toContain("secret");
  });

  it("rejects empty or oversized selections and missing systems", async () => {
    expect((await post({ findingIds: [], integrationIds: ["b1"] }))!.status).toBe(400);
    expect((await post({ findingIds: ["a", "b", "c", "d"], integrationIds: ["b1"] }))!.status).toBe(400);
    expect((await post({ findingIds: ["f1"], integrationIds: [] }))!.status).toBe(400);
    load.mockResolvedValue([]);
    expect((await post({ findingIds: ["f1"], integrationIds: ["gone"] }))!.status).toBe(400);
    expect(raise).not.toHaveBeenCalled();
  });

  it("files only this scan's findings and returns per-system results", async () => {
    const res = await post({ findingIds: ["f1", "f1"], integrationIds: ["b1"] });
    expect(res!.status).toBe(200);
    expect(findingRows.mock.calls[0][0].where).toEqual({ id: { in: ["f1"] }, scanId: "s1" });
    expect(raise.mock.calls[0][0].findings[0]).toMatchObject({ id: "f1", branch: "main" });
    expect((await res!.json()).results[0]).toMatchObject({ name: "Azure Boards (poc2)", created: 1 });
  });
});
