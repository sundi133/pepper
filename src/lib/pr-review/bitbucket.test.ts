import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  scan: { findFirst: vi.fn() },
  prReviewState: { findUnique: vi.fn(), upsert: vi.fn(async (_a: unknown) => ({})) },
  project: { findFirst: vi.fn(), update: vi.fn(async (_a: unknown) => ({})) },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
const AUTH = { username: "", appPassword: "", token: "ATCTT-x", authType: "access_token" as const };
const conn = vi.hoisted(() => ({ auth: null as unknown }));
vi.mock("@/lib/bitbucket-connection", () => ({ getOrgBitbucketAuth: async () => conn.auth }));
const api = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(async (..._a: unknown[]) => ({ ok: true, status: 201, data: {}, raw: "" })),
}));
vi.mock("@/lib/bitbucket-api", async (orig) => ({
  ...(await orig<typeof import("@/lib/bitbucket-api")>()),
  bitbucketGet: (...a: unknown[]) => api.get(...a),
  bitbucketPost: (...a: unknown[]) => api.post(...a),
}));
const queue = vi.hoisted(() => vi.fn(async (_p: Record<string, unknown>) => ({ scanId: "s1", status: "QUEUED" as const })));
vi.mock("@/lib/bitbucket-webhook-scan", () => ({ queueBitbucketWebhookScan: (p: Record<string, unknown>) => queue(p) }));
const create = vi.hoisted(() => vi.fn(async (_a: Record<string, unknown>) => ({ id: "p-new" })));
vi.mock("@/lib/create-project-with-build-gate", () => ({ createProjectWithBuildGate: (a: Record<string, unknown>) => create(a) }));
const remediate = vi.hoisted(() => vi.fn());
vi.mock("@/lib/remediation/start-run", () => ({ startRemediationRun: (...a: unknown[]) => remediate(...a) }));

import { BITBUCKET_BOT_MARKER, ensureProjectForBitbucketRepo, handleBitbucketComment, handleBitbucketPullRequest, type BitbucketPr } from "./bitbucket";
import { buildFindingMarker } from "@/lib/github-pr-inline-format";

process.env.NEXTAUTH_URL = "https://pepper.example";
const project = { id: "p1", organizationId: "o1", repoUrl: "https://bitbucket.org/acme/api.git", defaultBranch: "main" } as never;
const pr = (over: Partial<BitbucketPr> = {}): BitbucketPr => ({
  id: 12, state: "OPEN", draft: false,
  author: { uuid: "{u-alice}", nickname: "alice", display_name: "Alice", type: "user" },
  source: { branch: { name: "feature" }, commit: { hash: "head1" }, repository: { full_name: "acme/api" } },
  destination: { branch: { name: "main" }, commit: { hash: "base1" }, repository: { full_name: "acme/api" } },
  ...over,
});
const ok = (data: unknown, raw = "") => ({ ok: true, status: 200, data, raw });
const notFound = { ok: false, status: 404, data: {}, raw: "" };
function bitbucket(over: { config?: string; permission?: string; pr?: BitbucketPr; parent?: string } = {}) {
  api.get.mockImplementation(async (_a: unknown, path: string) => {
    if (path.includes("/src/")) return over.config ? ok({}, over.config) : notFound;
    if (path.includes("/permissions-config/users/")) return over.permission ? ok({ permission: over.permission }) : { ok: false, status: 403, data: {}, raw: "" };
    if (/\/pullrequests\/12$/.test(path)) return ok(over.pr ?? pr());
    if (/\/comments\/\d+$/.test(path)) return ok({ content: { raw: over.parent ?? "" } });
    return notFound;
  });
}
const statuses = () => api.post.mock.calls.filter((c) => String(c[1]).endsWith("/statuses/build")).map((c) => c[2] as { state: string; description: string; key: string });

beforeEach(() => {
  vi.clearAllMocks();
  conn.auth = AUTH;
  db.scan.findFirst.mockResolvedValue(null);
  db.prReviewState.findUnique.mockResolvedValue(null);
  bitbucket();
});

describe("Bitbucket pull requests", () => {
  it("reviews a new PR's head against the destination and marks it in progress", async () => {
    const r = await handleBitbucketPullRequest(project, "acme/api", "pullrequest:created", pr());
    expect(r).toMatchObject({ message: "Review queued", scanId: "s1" });
    expect(queue.mock.calls[0][0]).toMatchObject({ scanType: "INCREMENTAL", repoUrl: "https://bitbucket.org/acme/api.git", branch: "feature", commitSha: "head1", baseSha: "base1", prNumber: 12 });
    expect(statuses()[0]).toMatchObject({ key: "pepper-security", state: "INPROGRESS", description: "Pepper: review queued" });
    expect(String(api.get.mock.calls.find((c) => String(c[1]).includes("/src/"))![1])).toBe("/repositories/acme/api/src/base1/.pepper.yaml");
  });

  it("ignores updates whose head was already reviewed (titles, reviewers…)", async () => {
    db.scan.findFirst.mockResolvedValue({ id: "earlier" });
    expect((await handleBitbucketPullRequest(project, "acme/api", "pullrequest:updated", pr())).message).toMatch(/already reviewed/);
    expect(queue).not.toHaveBeenCalled();
  });

  it("skips drafts when .pepper.yaml says so, with a successful status; declined PRs are ignored", async () => {
    bitbucket({ config: "reviews:\n  drafts: false\n" });
    expect((await handleBitbucketPullRequest(project, "acme/api", "pullrequest:created", pr({ draft: true }))).message).toMatch(/draft/);
    expect(statuses()[0]).toMatchObject({ state: "SUCCESSFUL" });
    expect((await handleBitbucketPullRequest(project, "acme/api", "pullrequest:updated", pr({ state: "DECLINED" }))).message).toMatch(/declined/);
    expect(queue).not.toHaveBeenCalled();
  });

  it("clones a fork from the fork when its author can write; holds it otherwise", async () => {
    const fork = pr({ source: { branch: { name: "patch" }, commit: { hash: "f1" }, repository: { full_name: "mallory/api" } } });
    bitbucket({ permission: "write" });
    await handleBitbucketPullRequest(project, "acme/api", "pullrequest:created", fork);
    expect(queue.mock.calls[0][0]).toMatchObject({ repoUrl: "https://bitbucket.org/mallory/api.git", branch: "patch", commitSha: "f1" });

    vi.clearAllMocks();
    bitbucket(); // permission unknown (token without Admin)
    expect((await handleBitbucketPullRequest(project, "acme/api", "pullrequest:created", fork)).message).toMatch(/outside contributor/);
    expect(statuses()[0]).toMatchObject({ state: "INPROGRESS" });
    expect(queue).not.toHaveBeenCalled();
  });

  it("refuses a fork name that isn't one", async () => {
    const odd = pr({ source: { branch: { name: "x" }, commit: { hash: "f" }, repository: { full_name: "evil.example/../x" } } });
    expect((await handleBitbucketPullRequest(project, "acme/api", "pullrequest:created", odd)).message).toMatch(/unknown fork/);
  });

  it("treats app users as bots when bots are skipped", async () => {
    bitbucket({ config: "reviews:\n  bots: false\n" });
    expect((await handleBitbucketPullRequest(project, "acme/api", "pullrequest:created", pr({ author: { type: "app_user", nickname: "deps" } }))).message).toMatch(/bot/);
  });

  it("still reviews without a connection, as before (no config or status)", async () => {
    conn.auth = null;
    expect((await handleBitbucketPullRequest(project, "acme/api", "pullrequest:created", pr())).message).toBe("Review queued");
    expect(api.get).not.toHaveBeenCalled();
    expect(api.post).not.toHaveBeenCalled();
  });
});

describe("Bitbucket @pepper commands", () => {
  const deferred: Array<() => Promise<void>> = [];
  const defer = (w: () => Promise<void>) => void deferred.push(w);
  const run = async () => {
    while (deferred.length) await deferred.shift()!();
  };
  const event = (raw: string, over: Record<string, unknown> = {}, isPrivate = true) => ({
    comment: { id: 70, content: { raw }, user: { uuid: "{u-alice}", display_name: "Alice", type: "user" }, ...over },
    pullrequest: pr(),
    repository: { full_name: "acme/api", is_private: isPrivate },
  });
  const replies = () => api.post.mock.calls.filter((c) => String(c[1]).endsWith("/pullrequests/12/comments")).map((c) => c[2] as { content: { raw: string }; parent: { id: number } });

  it("ignores Pepper's own and bot comments", async () => {
    expect((await handleBitbucketComment(project, "acme/api", event(`${BITBUCKET_BOT_MARKER}\n@pepper review`), defer)).message).toMatch(/Ignored/);
    expect((await handleBitbucketComment(project, "acme/api", event("@pepper review", { user: { type: "app_user" } }), defer)).message).toMatch(/Ignored/);
    expect((await handleBitbucketComment(project, "acme/api", event("nice"), defer)).message).toBe("No command");
  });

  it("checks write access when it can, else allows commands only on private repositories", async () => {
    bitbucket({ permission: "read" });
    expect((await handleBitbucketComment(project, "acme/api", event("@pepper pause"), defer)).message).toMatch(/not a collaborator/);
    bitbucket(); // can't check
    expect((await handleBitbucketComment(project, "acme/api", event("@pepper pause", {}, false), defer)).message).toMatch(/not a collaborator/);
    expect(db.prReviewState.upsert).not.toHaveBeenCalled();
    expect((await handleBitbucketComment(project, "acme/api", event("@pepper pause"), defer)).message).toBe("pause");
    expect(db.prReviewState.upsert.mock.calls[0][0]).toMatchObject({ create: { projectId: "p1", prNumber: 12, paused: true, pausedBy: "Alice" } });
    expect(replies().at(-1)).toMatchObject({ parent: { id: 70 }, content: { raw: expect.stringContaining(BITBUCKET_BOT_MARKER) } });
  });

  it("queues a review after the response, from the PR's current head", async () => {
    bitbucket({ permission: "admin", pr: pr({ source: { branch: { name: "feature" }, commit: { hash: "head9" }, repository: { full_name: "acme/api" } } }) });
    await handleBitbucketComment(project, "acme/api", event("@pepper full review"), defer);
    expect(queue).not.toHaveBeenCalled();
    await run();
    expect(queue.mock.calls[0][0]).toMatchObject({ scanType: "FULL", commitSha: "head9", prNumber: 12 });
  });

  it("@pepper fix reads the finding from the parent Pepper comment", async () => {
    const finding = { id: "f1", title: "SQL injection", description: "d", severity: "HIGH", filePath: "a.py", startLine: 3, ruleId: "r", cweId: "CWE-89" };
    bitbucket({ permission: "write", parent: `${buildFindingMarker(finding)}\n**SQL injection**` });
    db.scan.findFirst.mockResolvedValue({ id: "scan-pr", findings: [finding] });
    remediate.mockResolvedValue({ ok: true, runId: "run1" });
    await handleBitbucketComment(project, "acme/api", event("@pepper fix", { parent: { id: 55 } }), defer);
    await run();
    expect(api.get.mock.calls.some((c) => String(c[1]).endsWith("/pullrequests/12/comments/55"))).toBe(true);
    expect(remediate).toHaveBeenCalledWith({ organizationId: "o1", userId: null, scanId: "scan-pr", findingIds: ["f1"], via: "pr-comment" });
    expect(replies().at(-1)!.content.raw).toMatch(/Working on a fix/);
  });
});

describe("Bitbucket onboarding", () => {
  it("creates the repository on bitbucket.org with its main branch", async () => {
    db.project.findFirst.mockResolvedValue(null);
    api.get.mockResolvedValue(ok({ mainbranch: { name: "develop" } }));
    expect(await ensureProjectForBitbucketRepo("o1", { full_name: "acme/api", uuid: "{abc-123}" })).toBe(true);
    expect(create.mock.calls[0][0]).toEqual({ organizationId: "o1", name: "acme/api", repoUrl: "https://bitbucket.org/acme/api.git", defaultBranch: "develop" });
    expect(db.project.update.mock.calls[0][0]).toMatchObject({ data: { bitbucketWorkspace: "acme", bitbucketRepoSlug: "api", bitbucketRepoUuid: "abc-123", connectedViaBitbucket: true } });
  });

  it("refuses unsafe names, missing uuids, and needs a connection", async () => {
    expect(await ensureProjectForBitbucketRepo("o1", { full_name: "acme/../x", uuid: "{a}" })).toBe(false);
    expect(await ensureProjectForBitbucketRepo("o1", { full_name: "acme/api" })).toBe(false);
    conn.auth = null;
    expect(await ensureProjectForBitbucketRepo("o1", { full_name: "acme/api", uuid: "{a}" })).toBe(false);
    expect(create).not.toHaveBeenCalled();
  });
});
