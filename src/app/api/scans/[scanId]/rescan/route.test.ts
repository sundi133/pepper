import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "org1"),
  requireRole: vi.fn(async () => ({ session: {}, membership: { role: "ADMIN" } })),
}));
const originalScan = {
  id: "scan1",
  projectId: "p1",
  sourceType: "UPLOAD",
  sourceRef: "scans/first/source.zip",
  scanType: "FULL",
  branch: null,
  baseSha: null,
  commitSha: null,
  prNumber: null,
  project: { name: "app", buildGate: null, connectedViaGithub: false, connectedViaBitbucket: false, connectedViaAzure: false },
};
const scanCreate = vi.fn(async () => ({ id: "scan2", projectId: "p1" }));
vi.mock("@/lib/prisma", () => ({
  prisma: {
    scan: {
      findFirst: vi.fn(async () => originalScan),
      create: (...a: unknown[]) => scanCreate(...(a as [])),
      update: vi.fn(async () => ({})),
    },
    orgSettings: { findUnique: vi.fn(async () => null) },
  },
}));
const removeAll = vi.fn(async () => undefined);
vi.mock("@/lib/active-project-scans", () => ({ cancelActiveScansForProject: (...a: unknown[]) => removeAll(...(a as [])) }));
vi.mock("@/lib/queue", () => ({ scanQueue: { add: vi.fn(async () => ({ id: "job1" })) } }));
vi.mock("@/lib/org-settings-job", () => ({ buildOrgSettingsForJob: vi.fn(() => ({})) }));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: vi.fn(async () => undefined), ipFromHeaders: vi.fn(() => null) }));
vi.mock("@/lib/scan-notifications", () => ({ createScanQueuedNotification: vi.fn(async () => undefined) }));
let exists: boolean | null = true;
vi.mock("@/lib/minio", () => ({ objectExists: vi.fn(async () => exists) }));

import { POST } from "./route";

const call = async () => {
  const res = await POST(new NextRequest("http://localhost/api/scans/scan1/rescan", { method: "POST" }), {
    params: Promise.resolve({ scanId: "scan1" }),
  });
  if (!res) throw new Error("no response");
  return res;
};

beforeEach(() => {
  vi.clearAllMocks();
  exists = true;
  delete process.env.UPLOAD_RETENTION_DAYS;
});

describe("rescan of an uploaded project", () => {
  it("rescans as before while the archive exists", async () => {
    const res = await call();
    expect(res.status).toBeLessThan(300);
    // Earlier scans are kept; only one still in progress is stopped.
    expect(removeAll).toHaveBeenCalledWith("p1");
    expect(scanCreate).toHaveBeenCalled();
  });

  it("refuses without touching the current results when retention deleted the archive", async () => {
    exists = false;
    process.env.UPLOAD_RETENTION_DAYS = "30";
    const res = await call();
    expect(res.status).toBe(410);
    expect((await res.json()).error).toMatch(/deleted by the data retention policy \(uploads are kept 30 days\).*Upload the archive again/);
    expect(removeAll).not.toHaveBeenCalled();
    expect(scanCreate).not.toHaveBeenCalled();
  });

  it("carries on as before when storage can't be asked", async () => {
    exists = null;
    const res = await call();
    expect(res.status).toBeLessThan(300);
    expect(removeAll).toHaveBeenCalled();
  });
});
