import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  getActiveOrgId: vi.fn(async () => "o1"),
  requireRole: vi.fn(async () => ({ session: {}, membership: { role: "DEVELOPER" } })),
}));
const db = vi.hoisted(() => ({
  project: { findFirst: vi.fn<(args: { where: unknown }) => Promise<unknown>>() },
  orgSettings: { findUnique: vi.fn(async () => null) },
  scan: {
    create: vi.fn<(args: { data: unknown }) => Promise<{ id: string }>>(async () => ({ id: "s1" })),
    update: vi.fn<(args: unknown) => Promise<unknown>>(async () => ({})),
  },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
const queueAdd = vi.hoisted(() => vi.fn(async () => ({ id: "job1" })));
vi.mock("@/lib/queue", () => ({ scanQueue: { add: queueAdd } }));
vi.mock("@/lib/minio", () => ({ uploadObject: vi.fn(), ensureBucket: vi.fn() }));
const audit = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: audit, ipFromHeaders: vi.fn(() => "1.2.3.4") }));
vi.mock("@/lib/active-project-scans", () => ({ cancelActiveScansForProject: vi.fn(async () => undefined) }));
vi.mock("@/lib/github-connection", () => ({ getOrgGithubAccessToken: vi.fn(async () => null) }));
vi.mock("@/lib/org-settings-job", () => ({ buildOrgSettingsForJob: vi.fn(() => ({})) }));
vi.mock("@/lib/scan-notifications", () => ({ createScanQueuedNotification: vi.fn(async () => undefined) }));
const createProject = vi.hoisted(() => vi.fn(async () => ({ id: "p-new" })));
vi.mock("@/lib/create-project-with-build-gate", () => ({ createProjectWithBuildGate: createProject }));

import { POST } from "./route";

const post = async (body: unknown) =>
  (await POST(
    new NextRequest("http://localhost/api/scans", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  ))!;

beforeEach(() => {
  vi.clearAllMocks();
  db.project.findFirst.mockResolvedValue({ id: "p1", name: "app", organizationId: "o1", buildGate: null });
});

describe("POST /api/scans (JSON)", () => {
  it("requires a source", async () => {
    const res = await post({ projectId: "p1" });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("Provide a repository URL, SVN URL, or upload a source archive");
    expect(db.scan.create).not.toHaveBeenCalled();
  });

  it("queues a git scan of an existing repository", async () => {
    const res = await post({ projectId: "p1", repoUrl: "https://github.com/acme/app", branch: "dev", scanType: "SAST_ONLY" });
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ scanId: "s1", projectId: "p1", status: "QUEUED" });
    expect(db.project.findFirst.mock.calls[0][0].where).toEqual({ id: "p1", organizationId: "o1" });
    expect(db.scan.create.mock.calls[0][0].data).toMatchObject({
      projectId: "p1",
      scanType: "SAST_ONLY",
      branch: "dev",
      sourceType: "GIT_CLONE",
      triggeredBy: "u1",
      status: "QUEUED",
    });
    expect(queueAdd).toHaveBeenCalledWith("scan", expect.objectContaining({ scanId: "s1", repoUrl: "https://github.com/acme/app" }), { jobId: "s1" });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "scan.queued",
        resourceId: "s1",
        ipAddress: "1.2.3.4",
        details: { scanType: "SAST_ONLY", sourceType: "GIT_CLONE" },
      }),
    );
  });

  it("creates the repository for a new URL", async () => {
    db.project.findFirst.mockResolvedValue({ id: "p-new", name: "lib", organizationId: "o1", buildGate: null });
    const res = await post({ repoUrl: "https://github.com/acme/lib.git" });
    expect(res.status).toBe(201);
    expect(createProject).toHaveBeenCalledWith(
      expect.objectContaining({ organizationId: "o1", repoUrl: "https://github.com/acme/lib.git", defaultBranch: "main" }),
    );
  });

  it("404s for another organization's repository and 503s when the queue is down", async () => {
    db.project.findFirst.mockResolvedValueOnce(null);
    expect((await post({ projectId: "theirs", repoUrl: "https://x/y" })).status).toBe(404);

    queueAdd.mockRejectedValueOnce(new Error("redis down"));
    const res = await post({ projectId: "p1", repoUrl: "https://x/y" });
    expect(res.status).toBe(503);
    expect(db.scan.update).toHaveBeenCalledWith({ where: { id: "s1" }, data: { status: "FAILED" } });
  });
});
