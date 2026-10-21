import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const { uploadObject, queueAdd, scanUpdate } = vi.hoisted(() => ({
  uploadObject: vi.fn(),
  queueAdd: vi.fn<(...args: unknown[]) => Promise<{ id: string }>>(async () => ({ id: "job1" })),
  scanUpdate: vi.fn(),
}));

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  requireRole: vi.fn(async () => ({})),
}));
vi.mock("@/lib/prisma", () => ({
  prisma: {
    project: { findFirst: vi.fn(async () => ({ id: "p1", name: "app", organizationId: "o1", buildGate: null })) },
    orgSettings: { findUnique: vi.fn(async () => null) },
    scan: { create: vi.fn(async () => ({ id: "s1" })), update: scanUpdate },
  },
}));
vi.mock("@/lib/queue", () => ({ scanQueue: { add: queueAdd } }));
vi.mock("@/lib/minio", () => ({ uploadObject, ensureBucket: vi.fn() }));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: vi.fn(), ipFromHeaders: vi.fn() }));
vi.mock("@/lib/active-project-scans", () => ({ cancelActiveScansForProject: vi.fn() }));
vi.mock("@/lib/github-connection", () => ({ getOrgGithubAccessToken: vi.fn(async () => null) }));
vi.mock("@/lib/org-settings-job", () => ({ buildOrgSettingsForJob: vi.fn(() => ({})) }));
vi.mock("@/lib/scan-notifications", () => ({ createScanQueuedNotification: vi.fn() }));

import { POST } from "./route";

async function upload(fileName: string, type = "", extra: Record<string, unknown> = {}) {
  const form = new FormData();
  form.append("file", new File([Buffer.from("PK\u0003\u0004 test")], fileName, { type }));
  form.append("data", JSON.stringify({ projectId: "p1", scanType: "FULL", ...extra }));
  const res = await POST(new NextRequest("http://localhost/api/scans", { method: "POST", body: form }));
  return res!;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("POST /api/scans uploads", () => {
  it("accepts a single compiled artifact and stores it under its own name", async () => {
    const res = await upload("app-release.apk", "application/vnd.android.package-archive");
    expect(res.status).toBe(201);
    expect(uploadObject).toHaveBeenCalledWith("scans/s1/compiled/app-release.apk", expect.any(Buffer), "application/octet-stream");
    expect(queueAdd.mock.calls[0][1]).toMatchObject({ sourceType: "UPLOAD", sourceRef: "scans/s1/compiled/app-release.apk" });
  });

  it("accepts .NET assemblies sent as octet-stream", async () => {
    const res = await upload("My App.dll", "application/octet-stream");
    expect(res.status).toBe(201);
    expect(uploadObject.mock.calls[0][0]).toBe("scans/s1/compiled/My_App.dll");
  });

  it("still stores source archives as before", async () => {
    const res = await upload("project.zip", "application/zip");
    expect(res.status).toBe(201);
    expect(uploadObject).toHaveBeenCalledWith("scans/s1/source.zip", expect.any(Buffer), "application/zip");
  });

  it("rejects other file types", async () => {
    const res = await upload("notes.txt", "text/plain");
    expect(res.status).toBe(400);
    expect(uploadObject).not.toHaveBeenCalled();
  });

  it("rejects an artifact with an implausible MIME type", async () => {
    const res = await upload("app.jar", "text/html");
    expect(res.status).toBe(400);
  });
});

describe("POST /api/scans GPT-6 Astra mobile review", () => {
  it("does not request the review unless asked", async () => {
    const res = await upload("app-release.apk", "application/vnd.android.package-archive");
    expect(res.status).toBe(201);
    expect(queueAdd.mock.calls[0][1]).toMatchObject({ aiMobileReview: false });
  });

  it("passes the review request for an Android app to the worker", async () => {
    const res = await upload("app-release.apk", "application/vnd.android.package-archive", { aiMobileReview: true });
    expect(res.status).toBe(201);
    expect(queueAdd.mock.calls[0][1]).toMatchObject({ aiMobileReview: true, sourceRef: "scans/s1/compiled/app-release.apk" });
  });

  it("accepts an iOS app with the review and stores it under its own name", async () => {
    const res = await upload("MyApp.ipa", "application/octet-stream", { aiMobileReview: true });
    expect(res.status).toBe(201);
    expect(uploadObject.mock.calls[0][0]).toBe("scans/s1/compiled/MyApp.ipa");
    expect(queueAdd.mock.calls[0][1]).toMatchObject({ aiMobileReview: true, sourceRef: "scans/s1/compiled/MyApp.ipa" });
  });

  it("rejects an iOS app without the review (nothing else can scan it)", async () => {
    const res = await upload("MyApp.ipa", "application/octet-stream");
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/GPT-6 Astra/);
    expect(uploadObject).not.toHaveBeenCalled();
  });

  it("ignores the request for files that are not mobile apps", async () => {
    const res = await upload("service.jar", "application/java-archive", { aiMobileReview: true });
    expect(res.status).toBe(201);
    expect(queueAdd.mock.calls[0][1]).toMatchObject({ aiMobileReview: false });
  });
});
