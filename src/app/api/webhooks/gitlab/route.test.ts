import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const auth = vi.hoisted(() => ({ result: { ok: true, organizationId: "o1" } as { ok: boolean; organizationId?: string | null } }));
vi.mock("@/lib/webhook-secrets", () => ({ requireGitlabWebhookAuth: async () => auth.result }));
const db = vi.hoisted(() => ({ project: { update: vi.fn(async (_a: unknown) => ({})) } }));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
vi.mock("@/lib/gitlab-connection", () => ({ getOrgGitLabAuth: async () => ({ hostUrl: "https://gitlab.com", accessToken: "t" }) }));
const find = vi.hoisted(() => vi.fn());
const queue = vi.hoisted(() => vi.fn(async (_p: Record<string, unknown>) => ({ scanId: "s1", status: "QUEUED" })));
vi.mock("@/lib/gitlab-webhook-scan", () => ({
  findProjectForGitLabWebhook: (...a: unknown[]) => find(...a),
  queueGitLabWebhookScan: (p: Record<string, unknown>) => queue(p),
  mainBranchWebhookScanType: () => "INCREMENTAL",
}));
const bot = vi.hoisted(() => ({
  ensure: vi.fn(async (..._a: unknown[]) => true),
  mr: vi.fn(async (..._a: unknown[]) => ({ message: "Review queued" })),
  note: vi.fn(async (..._a: unknown[]) => ({ message: "pause" })),
}));
vi.mock("@/lib/pr-review/gitlab", async (orig) => ({
  ...(await orig<typeof import("@/lib/pr-review/gitlab")>()),
  ensureProjectForGitLab: (...a: unknown[]) => bot.ensure(...a),
  handleGitLabMergeRequest: (...a: unknown[]) => bot.mr(...a),
  handleGitLabNote: (...a: unknown[]) => bot.note(...a),
}));

import { POST } from "./route";

const project = { id: "p1", organizationId: "o1", repoUrl: "https://gitlab.com/acme/api", defaultBranch: "main", gitlabProjectId: 42 };
const post = async (body: unknown) => (await POST(new NextRequest("http://localhost/api/webhooks/gitlab", { method: "POST", body: JSON.stringify(body) })))!.json();
const glProject = { id: 42, path_with_namespace: "acme/api", default_branch: "main" };

beforeEach(() => {
  vi.clearAllMocks();
  auth.result = { ok: true, organizationId: "o1" };
  find.mockResolvedValue(project);
});

describe("GitLab webhook", () => {
  it("rejects a bad secret", async () => {
    auth.result = { ok: false };
    const res = await POST(new NextRequest("http://localhost/api/webhooks/gitlab", { method: "POST", body: "{}" }));
    expect(res!.status).toBe(401);
  });

  it("hands merge request events to the review bot", async () => {
    expect(await post({ object_kind: "merge_request", project: glProject, object_attributes: { iid: 5, action: "open" } })).toEqual({ message: "Review queued" });
    expect(find).toHaveBeenCalledWith(42, "acme/api", "o1", "https://gitlab.com");
    expect(bot.mr).toHaveBeenCalledTimes(1);
  });

  it("scans pushes to the default branch only", async () => {
    expect(await post({ object_kind: "push", project: glProject, ref: "refs/heads/main", after: "abc123" })).toMatchObject({ trigger: "push_default_branch" });
    expect(queue.mock.calls[0][0]).toMatchObject({ branch: "main", commitSha: "abc123", repoUrl: "https://gitlab.com/acme/api" });
    expect(await post({ object_kind: "push", project: glProject, ref: "refs/heads/feature", after: "abc123" })).toEqual({ message: "Event ignored" });
    expect(queue).toHaveBeenCalledTimes(1);
  });

  it("onboards unknown projects from an organization's hook, not from notes or the env-only secret", async () => {
    find.mockResolvedValueOnce(null).mockResolvedValueOnce(project);
    await post({ object_kind: "merge_request", project: glProject, object_attributes: { iid: 5, action: "open" } });
    expect(bot.ensure).toHaveBeenCalledWith("o1", glProject);

    vi.clearAllMocks();
    find.mockResolvedValue(null);
    expect(await post({ object_kind: "note", project: glProject, object_attributes: { note: "@pepper review" } })).toEqual({ message: "No matching project found" });
    auth.result = { ok: true, organizationId: null };
    await post({ object_kind: "merge_request", project: glProject, object_attributes: { iid: 5, action: "open" } });
    expect(bot.ensure).not.toHaveBeenCalled();
  });

  it("remembers the GitLab project id on a project matched by path", async () => {
    find.mockResolvedValue({ ...project, gitlabProjectId: null });
    await post({ object_kind: "merge_request", project: glProject, object_attributes: { iid: 5, action: "open" } });
    expect(db.project.update.mock.calls[0][0]).toMatchObject({ where: { id: "p1" }, data: { gitlabProjectId: 42, gitlabNamespace: "acme/api" } });
    expect((bot.mr.mock.calls[0][0] as { gitlabProjectId: number }).gitlabProjectId).toBe(42);
  });

  it("ignores other events", async () => {
    expect(await post({ object_kind: "pipeline", project: glProject })).toEqual({ message: "Event ignored" });
    expect(find).not.toHaveBeenCalled();
  });
});
