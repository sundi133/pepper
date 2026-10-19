import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  scan: { findFirst: vi.fn() },
  prReviewState: { findUnique: vi.fn(), upsert: vi.fn(async (_a: unknown) => ({})) },
  project: { findFirst: vi.fn(), update: vi.fn(async (_a: unknown) => ({})) },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
const AUTH = { hostUrl: "https://gitlab.example.com", accessToken: "glpat-x" };
const conn = vi.hoisted(() => ({ auth: null as unknown }));
vi.mock("@/lib/gitlab-connection", () => ({ getOrgGitLabAuth: async () => conn.auth }));
const api = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(async (..._a: unknown[]) => ({ ok: true, status: 201, data: {}, raw: "" })),
}));
vi.mock("@/lib/gitlab-api", async (orig) => ({
  ...(await orig<typeof import("@/lib/gitlab-api")>()),
  gitlabGet: (...a: unknown[]) => api.get(...a),
  gitlabPost: (...a: unknown[]) => api.post(...a),
}));
const statusCalls = vi.hoisted(() => vi.fn(async (_s: Record<string, unknown>) => undefined));
vi.mock("@/lib/gitlab-commit-status", () => ({ postGitLabCommitStatus: (s: Record<string, unknown>) => statusCalls(s) }));
const queue = vi.hoisted(() => vi.fn(async (_p: Record<string, unknown>) => ({ scanId: "s1", status: "QUEUED" as const })));
vi.mock("@/lib/gitlab-webhook-scan", () => ({ queueGitLabWebhookScan: (p: Record<string, unknown>) => queue(p) }));
const create = vi.hoisted(() => vi.fn(async (_a: Record<string, unknown>) => ({ id: "p-new" })));
vi.mock("@/lib/create-project-with-build-gate", () => ({ createProjectWithBuildGate: (a: Record<string, unknown>) => create(a) }));
const remediate = vi.hoisted(() => vi.fn());
vi.mock("@/lib/remediation/start-run", () => ({ startRemediationRun: (...a: unknown[]) => remediate(...a) }));

import {
  GITLAB_BOT_MARKER,
  defaultBranchPush,
  ensureProjectForGitLab,
  handleGitLabMergeRequest,
  handleGitLabNote,
  reviewActionOf,
  type GitLabMergeRequestEvent,
} from "./gitlab";
import { buildFindingMarker } from "@/lib/github-pr-inline-format";

const project = {
  id: "p1",
  organizationId: "o1",
  repoUrl: "https://gitlab.example.com/acme/api.git",
  defaultBranch: "main",
  gitlabProjectId: 42,
} as never;
const mrEvent = (attrs: Record<string, unknown> = {}, over: Partial<GitLabMergeRequestEvent> = {}): GitLabMergeRequestEvent => ({
  user: { id: 7, username: "alice" },
  project: { id: 42, path_with_namespace: "acme/api" },
  object_attributes: {
    iid: 5, action: "open", state: "opened", draft: false,
    source_branch: "feature", target_branch: "main",
    source_project_id: 42, target_project_id: 42, author_id: 7,
    last_commit: { id: "head1" },
    ...attrs,
  },
  ...over,
});
const ok = (data: unknown, raw = "") => ({ ok: true, status: 200, data, raw });
const notFound = { ok: false, status: 404, data: {}, raw: "" };
/** The GitLab API, by path: the MR (for diff_refs), member access levels, no .pepper.yaml. */
function gitlab(over: { config?: string; access?: number; mr?: Record<string, unknown> } = {}) {
  api.get.mockImplementation(async (_a: unknown, path: string) => {
    if (path.includes("/repository/files/")) return over.config ? ok({}, over.config) : notFound;
    if (path.includes("/members/all/")) return over.access ? ok({ access_level: over.access, state: "active" }) : notFound;
    if (/\/merge_requests\/\d+$/.test(path)) return ok({ iid: 5, diff_refs: { base_sha: "base1", head_sha: "head1" }, sha: "head1", source_branch: "feature", target_branch: "main", source_project_id: 42, target_project_id: 42, ...over.mr });
    if (path.includes("/discussions/")) return ok({ notes: [] });
    return notFound;
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  conn.auth = AUTH;
  db.prReviewState.findUnique.mockResolvedValue(null);
  gitlab();
});

describe("which merge request events are reviewed", () => {
  it("maps open, reopen, pushes and draft → ready; ignores updates without new commits", () => {
    expect(reviewActionOf(mrEvent({ action: "open" }))).toBe("opened");
    expect(reviewActionOf(mrEvent({ action: "reopen" }))).toBe("reopened");
    expect(reviewActionOf(mrEvent({ action: "update", oldrev: "old1" }))).toBe("synchronize");
    expect(reviewActionOf(mrEvent({ action: "update" }, { changes: { draft: { previous: true, current: false } } }))).toBe("ready_for_review");
    expect(reviewActionOf(mrEvent({ action: "update" }, { changes: { draft: { previous: false, current: true } } }))).toBeNull();
    expect(reviewActionOf(mrEvent({ action: "update" }))).toBeNull(); // title, labels, assignee…
    expect(reviewActionOf(mrEvent({ action: "merge" }))).toBeNull();
  });
});

describe("GitLab merge requests", () => {
  it("queues a review of the head with the MR's base, and marks it pending", async () => {
    const r = await handleGitLabMergeRequest(project, mrEvent());
    expect(r).toMatchObject({ message: "Review queued", scanId: "s1" });
    expect(queue.mock.calls[0][0]).toMatchObject({ scanType: "INCREMENTAL", branch: "feature", commitSha: "head1", baseSha: "base1", prNumber: 5 });
    expect(queue.mock.calls[0][0].fetchRef).toBeUndefined();
    expect(statusCalls.mock.calls[0][0]).toMatchObject({ organizationId: "o1", gitlabProjectId: 42, sha: "head1", state: "pending", description: "Pepper: review queued" });
    expect(String(api.get.mock.calls.find((c) => String(c[1]).includes("/files/"))![1])).toBe("/projects/42/repository/files/.pepper.yaml/raw?ref=main");
  });

  it("ignores updates without new commits and closed merge requests", async () => {
    expect((await handleGitLabMergeRequest(project, mrEvent({ action: "update" }))).message).toMatch(/without new commits/);
    expect((await handleGitLabMergeRequest(project, mrEvent({ action: "update", oldrev: "o", state: "merged" }))).message).toMatch(/merged/);
    expect(queue).not.toHaveBeenCalled();
  });

  it("follows .pepper.yaml from the target branch: drafts skipped with a success status", async () => {
    gitlab({ config: "reviews:\n  drafts: false\n" });
    expect((await handleGitLabMergeRequest(project, mrEvent({ draft: true }))).message).toMatch(/draft/);
    expect(statusCalls.mock.calls[0][0]).toMatchObject({ state: "success", description: expect.stringMatching(/draft/) });
    expect(queue).not.toHaveBeenCalled();
  });

  it("reviews a fork from a project developer through the MR head ref; holds one from an outsider", async () => {
    gitlab({ access: 30 });
    await handleGitLabMergeRequest(project, mrEvent({ source_project_id: 99 }));
    expect(queue.mock.calls[0][0]).toMatchObject({ branch: "main", fetchRef: "refs/merge-requests/5/head", commitSha: "head1" });

    vi.clearAllMocks();
    gitlab({ access: 10 }); // Guest
    expect((await handleGitLabMergeRequest(project, mrEvent({ source_project_id: 99 }))).message).toMatch(/outside contributor/);
    expect(statusCalls.mock.calls[0][0]).toMatchObject({ state: "pending" });
    expect(queue).not.toHaveBeenCalled();
  });

  it("recognises GitLab's token bot users when bots are skipped", async () => {
    gitlab({ config: "reviews:\n  bots: false\n" });
    expect((await handleGitLabMergeRequest(project, mrEvent({}, { user: { id: 1, username: "project_42_bot_0123abcd" } }))).message).toMatch(/bot/);
    expect((await handleGitLabMergeRequest(project, mrEvent({}, { user: { id: 1, username: "renovate-bot" } }))).message).toMatch(/bot/);
  });

  it("respects a paused merge request", async () => {
    db.prReviewState.findUnique.mockResolvedValue({ paused: true });
    expect((await handleGitLabMergeRequest(project, mrEvent())).message).toMatch(/paused/);
  });

  it("still queues a review without a connection, as before (no config, statuses or base)", async () => {
    conn.auth = null;
    expect((await handleGitLabMergeRequest(project, mrEvent())).message).toBe("Review queued");
    expect(queue.mock.calls[0][0]).toMatchObject({ branch: "feature", commitSha: "head1", baseSha: undefined });
    expect(api.get).not.toHaveBeenCalled();
    expect(statusCalls).not.toHaveBeenCalled();
  });

  it("never sends the token for a project on another host", async () => {
    const elsewhere = { ...(project as object), repoUrl: "https://evil.example.net/acme/api.git" } as never;
    await handleGitLabMergeRequest(elsewhere, mrEvent());
    expect(api.get).not.toHaveBeenCalled();
    expect(statusCalls).not.toHaveBeenCalled();
  });
});

describe("pushes", () => {
  it("scans pushes to the default branch only", () => {
    expect(defaultBranchPush(project, { ref: "refs/heads/main", after: "abc" })).toEqual({ branch: "main", commitSha: "abc" });
    expect(defaultBranchPush(project, { ref: "refs/heads/feature", after: "abc" })).toBeNull();
    expect(defaultBranchPush(project, { ref: "refs/heads/main", after: "0000000000000000000000000000000000000000" })).toBeNull();
  });
});

describe("GitLab @pepper commands", () => {
  const deferred: Array<() => Promise<void>> = [];
  const defer = (w: () => Promise<void>) => void deferred.push(w);
  const run = async () => {
    while (deferred.length) await deferred.shift()!();
  };
  const noteEvent = (note: string, over: Record<string, unknown> = {}, mr: Record<string, unknown> = {}) => ({
    user: { id: 7, username: "alice" },
    project: { id: 42, path_with_namespace: "acme/api" },
    object_attributes: { id: 300, note, noteable_type: "MergeRequest", discussion_id: "d1", ...over },
    merge_request: { iid: 5, source_branch: "feature", target_branch: "main", source_project_id: 42, target_project_id: 42, last_commit: { id: "head1" }, ...mr },
  });
  const replies = () => api.post.mock.calls.filter((c) => String(c[1]).endsWith("/discussions/d1/notes")).map((c) => (c[2] as { body: string }).body);

  it("ignores Pepper's own, system and bot notes, and notes elsewhere", async () => {
    expect((await handleGitLabNote(project, noteEvent(`${GITLAB_BOT_MARKER}\n@pepper review`), defer)).message).toMatch(/Ignored/);
    expect((await handleGitLabNote(project, noteEvent("@pepper review", { system: true }), defer)).message).toMatch(/Ignored/);
    expect((await handleGitLabNote(project, { ...noteEvent("@pepper review"), user: { id: 1, username: "group_9_bot" } }, defer)).message).toMatch(/Ignored/);
    expect((await handleGitLabNote(project, noteEvent("@pepper review", { noteable_type: "Issue" }), defer)).message).toMatch(/not a merge request/);
    expect((await handleGitLabNote(project, noteEvent("looks good"), defer)).message).toBe("No command");
    expect(api.post).not.toHaveBeenCalled();
  });

  it("refuses members below Developer", async () => {
    gitlab({ access: 20 }); // Reporter
    expect((await handleGitLabNote(project, noteEvent("@pepper pause"), defer)).message).toMatch(/not a collaborator/);
    expect(replies()[0]).toMatch(/Developer access/);
    expect(db.prReviewState.upsert).not.toHaveBeenCalled();
  });

  it("acknowledges, replies in the discussion marked as Pepper's, and pauses", async () => {
    gitlab({ access: 40 });
    await handleGitLabNote(project, noteEvent("@pepper pause"), defer);
    expect(api.post.mock.calls.some((c) => c[1] === "/projects/42/merge_requests/5/notes/300/award_emoji" && (c[2] as { name: string }).name === "eyes")).toBe(true);
    expect(db.prReviewState.upsert.mock.calls[0][0]).toMatchObject({ create: { projectId: "p1", prNumber: 5, paused: true, pausedBy: "alice" } });
    expect(replies()[0]).toContain(GITLAB_BOT_MARKER);
  });

  it("queues a review after the response, from the merge request's current head", async () => {
    gitlab({ access: 30, mr: { sha: "head9", diff_refs: { base_sha: "base9", head_sha: "head9" } } });
    await handleGitLabNote(project, noteEvent("@pepper full review"), defer);
    expect(queue).not.toHaveBeenCalled();
    await run();
    expect(queue.mock.calls[0][0]).toMatchObject({ scanType: "FULL", commitSha: "head9", baseSha: "base9", prNumber: 5 });
  });

  it("@pepper fix starts a remediation run for the finding in a Pepper discussion, and refuses forks", async () => {
    const finding = { id: "f1", title: "SQL injection", description: "d", severity: "HIGH", filePath: "src/a.rb", startLine: 9, ruleId: "r", cweId: "CWE-89" };
    gitlab({ access: 30 });
    const base = api.get.getMockImplementation()!;
    api.get.mockImplementation(async (a: unknown, path: string) =>
      path.endsWith("/discussions/d1") ? ok({ notes: [{ body: `${buildFindingMarker(finding)}\n**SQL injection**` }] }) : base(a, path),
    );
    db.scan.findFirst.mockResolvedValue({ id: "scan-mr", findings: [finding] });
    remediate.mockResolvedValue({ ok: true, runId: "run1" });
    await handleGitLabNote(project, noteEvent("@pepper fix"), defer);
    await run();
    expect(remediate).toHaveBeenCalledWith({ organizationId: "o1", userId: null, scanId: "scan-mr", findingIds: ["f1"], via: "pr-comment" });
    expect(replies().at(-1)).toMatch(/Working on a fix/);
    expect((await handleGitLabNote(project, noteEvent("@pepper fix", {}, { source_project_id: 99 }), defer)).message).toMatch(/fork/);
  });
});

describe("GitLab onboarding", () => {
  it("creates the project with a clone URL built from the connection's host and the path", async () => {
    db.project.findFirst.mockResolvedValue(null);
    expect(await ensureProjectForGitLab("o1", { id: 42, path_with_namespace: "acme/backend/api", default_branch: "trunk" })).toBe(true);
    expect(create.mock.calls[0][0]).toEqual({ organizationId: "o1", name: "acme/backend/api", repoUrl: "https://gitlab.example.com/acme/backend/api.git", defaultBranch: "trunk" });
    expect(db.project.update.mock.calls[0][0]).toMatchObject({ data: { gitlabProjectId: 42, gitlabNamespace: "acme/backend/api", connectedViaGitlab: true } });
  });

  it("refuses incomplete or unsafe identities, and needs a connection", async () => {
    expect(await ensureProjectForGitLab("o1", { id: 42, path_with_namespace: "acme/../x" })).toBe(false);
    expect(await ensureProjectForGitLab("o1", { id: 42, path_with_namespace: "single" })).toBe(false);
    expect(await ensureProjectForGitLab("o1", { path_with_namespace: "acme/api" })).toBe(false);
    conn.auth = null;
    expect(await ensureProjectForGitLab("o1", { id: 42, path_with_namespace: "acme/api" })).toBe(false);
    expect(create).not.toHaveBeenCalled();
  });
});
