import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  project: { findFirst: vi.fn(async () => ({ id: "p1", name: "api", organizationId: "o1", buildGate: null, organization: {} })) },
  orgSettings: { findUnique: vi.fn(async () => null) },
  scan: { create: vi.fn(async () => ({ id: "s1" })), update: vi.fn(async () => ({})) },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
const jobs = vi.hoisted(() => [] as Array<Record<string, unknown>>);
vi.mock("@/lib/queue", () => ({ scanQueue: { add: vi.fn(async (_n: string, data: Record<string, unknown>) => (jobs.push(data), { id: "j1" })) } }));
vi.mock("@/lib/minio", () => ({ uploadObject: vi.fn(), ensureBucket: vi.fn() }));
vi.mock("@/lib/github-connection", () => ({ getOrgGithubAccessToken: vi.fn(async () => null) }));
vi.mock("@/lib/create-project-with-build-gate", () => ({ createProjectWithBuildGate: vi.fn(async () => ({ id: "p1" })) }));
vi.mock("@/lib/org-settings-job", () => ({ buildOrgSettingsForJob: () => ({ orgId: "o1" }) }));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: vi.fn() }));
vi.mock("@/lib/active-project-scans", () => ({ cancelActiveScansForProject: vi.fn() }));
vi.mock("@/lib/scan-notifications", () => ({ createScanQueuedNotification: vi.fn() }));
const policy = vi.hoisted(() => ({ allowed: true, source: "app" as "app" | "oauth" }));
vi.mock("@/lib/github-token-resolve", () => ({
  isPersonalGithubAllowed: async () => policy.allowed,
  resolveGithubToken: async () => ({ token: "t", source: policy.source }),
}));

import { queueNewScan } from "./scan-create";
import { decryptSecret } from "./token-encryption";

const TOKEN = "ghp_pastedPersonalToken1234567890abcd";

beforeEach(() => {
  vi.clearAllMocks();
  jobs.length = 0;
  policy.allowed = true;
  policy.source = "app";
  process.env.NEXTAUTH_SECRET ||= "test-secret-for-token-encryption-0123456789";
});

describe("credentials pasted for one scan", () => {
  it("travel encrypted in the job, never inside the clone URL", async () => {
    const r = await queueNewScan({ orgId: "o1", userId: "u1", scanParams: { projectId: "p1", scanType: "FULL", repoUrl: "https://github.com/acme/api.git", repoToken: TOKEN } as never });
    expect(r.ok).toBe(true);
    const job = jobs[0];
    expect(job.repoUrl).toBe("https://github.com/acme/api.git");
    expect(JSON.stringify(job)).not.toContain(TOKEN);
    expect(decryptSecret(job.repoTokenEnc as string)).toBe(TOKEN);
  });

  it("SVN passwords too", async () => {
    await queueNewScan({ orgId: "o1", userId: "u1", scanParams: { projectId: "p1", scanType: "FULL", svnUrl: "https://svn.corp/repo", svnUsername: "ci", svnPassword: "s3cr3t-svn-pass" } as never });
    const job = jobs[0];
    expect(JSON.stringify(job)).not.toContain("s3cr3t-svn-pass");
    expect(job.svnPassword).toBeUndefined();
    expect(decryptSecret(job.svnPasswordEnc as string)).toBe("s3cr3t-svn-pass");
  });

  it("are refused for App-covered repositories when the organization allows only the App", async () => {
    policy.allowed = false;
    const r = await queueNewScan({ orgId: "o1", userId: "u1", scanParams: { projectId: "p1", scanType: "FULL", repoUrl: "https://github.com/acme/api.git", repoToken: TOKEN } as never });
    expect(r).toMatchObject({ ok: false, status: 400, error: expect.stringMatching(/GitHub App for acme/) });
    expect(jobs).toHaveLength(0);
    policy.source = "oauth";
    expect((await queueNewScan({ orgId: "o1", userId: "u1", scanParams: { projectId: "p1", scanType: "FULL", repoUrl: "https://github.com/other/x.git", repoToken: TOKEN } as never })).ok).toBe(true);
  });
});
