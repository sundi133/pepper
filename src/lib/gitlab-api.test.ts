import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  orgGitLabConnection: { findUnique: vi.fn() },
  project: { findFirst: vi.fn(), findMany: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
vi.mock("./prisma", () => ({ prisma: db }));

import { gitlabProjectPath, isOnGitLabHost, withGitLabCredentials } from "./gitlab-api";
import { findProjectForGitLabWebhook } from "./gitlab-webhook-scan";
import { postGitLabCommitStatus, scanCommitStatus } from "./gitlab-commit-status";
import { describeGitLabToken } from "./gitlab-connection";

const AUTH = { hostUrl: "https://gitlab.example.com", accessToken: "glpat-s3cr3t" };

beforeEach(() => vi.clearAllMocks());

describe("GitLab clone credentials", () => {
  it("embeds the token only for the connection's host", () => {
    expect(withGitLabCredentials("https://gitlab.example.com/acme/api.git", AUTH)).toBe("https://oauth2:glpat-s3cr3t@gitlab.example.com/acme/api.git");
    expect(withGitLabCredentials("https://evil.example.net/acme/api.git", AUTH)).toBeNull();
    expect(withGitLabCredentials("http://gitlab.example.com/acme/api.git", AUTH)).toBeNull(); // another scheme
    expect(withGitLabCredentials("https://gitlab.example.com:8443/acme/api.git", AUTH)).toBeNull(); // another port
    expect(isOnGitLabHost("not a url", AUTH)).toBe(false);
  });

  it("reads the project path, including under a relative URL root", () => {
    expect(gitlabProjectPath("https://gitlab.com/acme/sub/api.git")).toBe("acme/sub/api");
    expect(gitlabProjectPath("https://host/gitlab/acme/api", { hostUrl: "https://host/gitlab" })).toBe("acme/api");
    expect(gitlabProjectPath("https://gitlab.com/single")).toBeNull();
    expect(gitlabProjectPath("https://gitlab.com/a/../b")).toBeNull();
  });
});

describe("finding the project for a GitLab event", () => {
  const p = (id: string, repoUrl: string) => ({ id, repoUrl });

  it("matches the GitLab project id first", async () => {
    db.project.findFirst.mockResolvedValue(p("by-id", "https://gitlab.com/acme/api"));
    expect((await findProjectForGitLabWebhook(42, "acme/api", "o1"))!.id).toBe("by-id");
    expect(db.project.findFirst.mock.calls[0][0]).toMatchObject({ where: { gitlabProjectId: 42, organizationId: "o1" } });
    expect(db.project.findMany).not.toHaveBeenCalled();
  });

  it("then matches the whole path only: acme/api is not acme/api-legacy or x/acme/api", async () => {
    db.project.findFirst.mockResolvedValue(null);
    db.project.findMany.mockResolvedValue([
      p("legacy", "https://gitlab.com/acme/api-legacy"),
      p("nested", "https://gitlab.com/x/acme/api"),
      p("right", "https://gitlab.com/Acme/API.git"),
    ]);
    expect((await findProjectForGitLabWebhook(42, "acme/api", "o1"))!.id).toBe("right");
    db.project.findMany.mockResolvedValue([p("legacy", "https://gitlab.com/acme/api-legacy")]);
    expect(await findProjectForGitLabWebhook(42, "acme/api", "o1")).toBeNull();
  });

  it("still matches projects stored with SSH or scheme-less URLs", async () => {
    db.project.findFirst.mockResolvedValue(null);
    db.project.findMany.mockResolvedValue([p("ssh", "git@gitlab.com:acme/api.git")]);
    expect((await findProjectForGitLabWebhook(42, "acme/api", "o1"))!.id).toBe("ssh");
    db.project.findMany.mockResolvedValue([p("ssh-url", "ssh://git@gitlab.com:2222/acme/api.git")]);
    expect((await findProjectForGitLabWebhook(42, "acme/api", "o1"))!.id).toBe("ssh-url");
    db.project.findMany.mockResolvedValue([p("bare", "gitlab.com/acme/api")]);
    expect((await findProjectForGitLabWebhook(42, "acme/api", "o1"))!.id).toBe("bare");
  });

  it("accepts the connection's relative URL root", async () => {
    db.project.findFirst.mockResolvedValue(null);
    db.project.findMany.mockResolvedValue([p("rooted", "https://host/gitlab/acme/api")]);
    expect(await findProjectForGitLabWebhook(undefined, "acme/api", "o1")).toBeNull();
    expect((await findProjectForGitLabWebhook(undefined, "acme/api", "o1", "https://host/gitlab"))!.id).toBe("rooted");
  });
});

describe("GitLab commit statuses", () => {
  it("are posted only when the connection has them on", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 201 }));
    db.orgGitLabConnection.findUnique.mockResolvedValue({ commitStatuses: false });
    await postGitLabCommitStatus({ organizationId: "o1", auth: AUTH, gitlabProjectId: 42, sha: "abc1234", state: "pending", description: "x" });
    expect(f).not.toHaveBeenCalled();
    db.orgGitLabConnection.findUnique.mockResolvedValue({ commitStatuses: true });
    await postGitLabCommitStatus({ organizationId: "o1", auth: AUTH, gitlabProjectId: 42, sha: "abc1234", state: "pending", description: "x", targetUrl: "https://pepper/scans/s" });
    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gitlab.example.com/api/v4/projects/42/statuses/abc1234");
    expect(JSON.parse(String(init.body))).toEqual({ state: "pending", name: "pepper/security", description: "x", target_url: "https://pepper/scans/s" });
    f.mockRestore();
  });

  it("refuses a sha that isn't one", async () => {
    db.orgGitLabConnection.findUnique.mockResolvedValue({ commitStatuses: true });
    const f = vi.spyOn(globalThis, "fetch");
    await postGitLabCommitStatus({ organizationId: "o1", auth: AUTH, gitlabProjectId: 42, sha: "../../x", state: "success", description: "x" });
    expect(f).not.toHaveBeenCalled();
    f.mockRestore();
  });

  it("follows the build gate", () => {
    const none = { critical: 0, high: 0, medium: 0, low: 0 };
    expect(scanCommitStatus("FAILED", null, none)).toEqual({ state: "failed", description: "Pepper scan failed" });
    expect(scanCommitStatus("COMPLETED", "FAILED", { ...none, high: 2 })).toEqual({ state: "failed", description: "Build gate failed: 2 high" });
    expect(scanCommitStatus("COMPLETED", "PASSED", { ...none, low: 1 })).toEqual({ state: "success", description: "Build gate passed: 1 low" });
    expect(scanCommitStatus("COMPLETED", "PASSED", none)).toEqual({ state: "success", description: "No security findings" });
  });
});

describe("GitLab token description", () => {
  it("tells a bot token from a personal one, with scopes and expiry", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ scopes: ["api", "read_repository"], expires_at: "2027-01-31" }), { status: 200 }));
    const info = await describeGitLabToken(AUTH, { id: 9, username: "group_12_bot_ab", bot: true });
    expect(info).toEqual({ kind: "bot", scopes: ["api", "read_repository"], expiresAt: new Date("2027-01-31") });
    expect((await describeGitLabToken(AUTH, { id: 1, username: "alice" })).kind).toBe("personal");
    f.mockRestore();
  });

  it("still works when GitLab doesn't answer /personal_access_tokens/self (older servers)", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("not found", { status: 404 }));
    expect(await describeGitLabToken(AUTH, null)).toEqual({ kind: "personal", scopes: [], expiresAt: null });
    f.mockRestore();
  });
});
