import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  scan: { findFirst: vi.fn() },
  prReviewState: { findUnique: vi.fn(), upsert: vi.fn(async (_a: unknown) => ({})) },
  project: { findFirst: vi.fn(), update: vi.fn(async (_a: unknown) => ({})) },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
const AUTH = { organization: "contoso", pat: "", bearer: "tok" };
vi.mock("@/lib/azure-devops-connection", () => ({ getOrgAzureDevOpsAuth: async () => AUTH }));
const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(async (..._a: unknown[]) => ({ ok: true, status: 200, data: {} })) }));
vi.mock("@/lib/azure-devops-api", async (orig) => ({
  ...(await orig<typeof import("@/lib/azure-devops-api")>()),
  azureGet: (...a: unknown[]) => api.get(...a),
  azurePost: (...a: unknown[]) => api.post(...a),
}));
const queue = vi.hoisted(() => vi.fn(async (_p: Record<string, unknown>) => ({ scanId: "s1", status: "QUEUED" as const })));
vi.mock("@/lib/azure-devops-webhook-scan", () => ({ queueAzureDevOpsWebhookScan: (p: Record<string, unknown>) => queue(p) }));
const create = vi.hoisted(() => vi.fn(async (_a: Record<string, unknown>) => ({ id: "p-new" })));
vi.mock("@/lib/create-project-with-build-gate", () => ({ createProjectWithBuildGate: (a: Record<string, unknown>) => create(a) }));
const remediate = vi.hoisted(() => vi.fn());
vi.mock("@/lib/remediation/start-run", () => ({ startRemediationRun: (...a: unknown[]) => remediate(...a) }));

import { AZURE_BOT_MARKER, ensureProjectForAzureRepo, handleAzureComment, handleAzurePullRequest, threadIdOf } from "./azure-devops";
import { buildFindingMarker } from "@/lib/github-pr-inline-format";

const project = { id: "p1", organizationId: "o1", repoUrl: "https://dev.azure.com/contoso/Payments/_git/api", azureProjectName: "Payments", azureRepoId: "repo-guid", defaultBranch: "main" } as never;
const pr = (over: Record<string, unknown> = {}) => ({
  pullRequestId: 12, status: "active", isDraft: false,
  sourceRefName: "refs/heads/feature", targetRefName: "refs/heads/main",
  lastMergeSourceCommit: { commitId: "head1" }, lastMergeTargetCommit: { commitId: "base1" },
  createdBy: { uniqueName: "alice@contoso.com", displayName: "Alice" },
  ...over,
});
const notFound = { ok: false, status: 404, data: {} };
const statuses = () => api.post.mock.calls.filter((c) => String(c[1]).endsWith("/statuses")).map((c) => c[2] as { state: string; description: string });

beforeEach(() => {
  vi.clearAllMocks();
  db.scan.findFirst.mockResolvedValue(null);
  db.prReviewState.findUnique.mockResolvedValue(null);
  api.get.mockResolvedValue(notFound); // no .pepper.yaml
});

describe("Azure DevOps pull requests", () => {
  it("reviews a new PR's source commit and marks it pending", async () => {
    const r = await handleAzurePullRequest(project, "git.pullrequest.created", pr());
    expect(r).toMatchObject({ message: "Review queued", scanId: "s1" });
    expect(queue.mock.calls[0][0]).toMatchObject({ scanType: "INCREMENTAL", branch: "feature", commitSha: "head1", baseSha: "base1", prNumber: 12 });
    expect(statuses()[0]).toMatchObject({ state: "pending", description: "Pepper: review queued" });
    expect(String(api.get.mock.calls[0][1])).toMatch(/items\?path=%2F\.pepper\.yaml.*versionDescriptor\.version=main/);
  });

  it("ignores updates whose source commit was already reviewed (votes, titles…)", async () => {
    db.scan.findFirst.mockResolvedValue({ id: "earlier" });
    expect((await handleAzurePullRequest(project, "git.pullrequest.updated", pr())).message).toMatch(/already reviewed/);
    expect(queue).not.toHaveBeenCalled();
    db.scan.findFirst.mockResolvedValue(null);
    expect((await handleAzurePullRequest(project, "git.pullrequest.updated", pr({ lastMergeSourceCommit: { commitId: "head2" } }))).message).toBe("Review queued");
  });

  it("follows .pepper.yaml from the target branch: drafts skipped with a succeeded status", async () => {
    api.get.mockResolvedValue({ ok: true, status: 200, data: { content: "reviews:\n  drafts: false\n" } });
    expect((await handleAzurePullRequest(project, "git.pullrequest.created", pr({ isDraft: true }))).message).toMatch(/draft/);
    expect(statuses()[0]).toMatchObject({ state: "succeeded", description: expect.stringMatching(/draft/) });
    expect(queue).not.toHaveBeenCalled();
  });

  it("reviews fork PRs through the merge ref on the target branch, and skips closed PRs", async () => {
    await handleAzurePullRequest(project, "git.pullrequest.created", pr({ forkSource: { repository: {} } }));
    expect(queue.mock.calls[0][0]).toMatchObject({ branch: "main", fetchRef: "refs/pull/12/merge" });
    expect((await handleAzurePullRequest(project, "git.pullrequest.updated", pr({ status: "completed" }))).message).toMatch(/completed/);
  });

  it("respects a paused PR", async () => {
    db.prReviewState.findUnique.mockResolvedValue({ paused: true });
    expect((await handleAzurePullRequest(project, "git.pullrequest.created", pr())).message).toMatch(/paused/);
  });
});

describe("Azure DevOps @pepper commands", () => {
  const deferred: Array<() => Promise<void>> = [];
  const defer = (w: () => Promise<void>) => void deferred.push(w);
  const run = async () => {
    while (deferred.length) await deferred.shift()!();
  };
  const comment = (content: string, over: Record<string, unknown> = {}) => ({
    id: 3, content, commentType: "text", author: { displayName: "Alice" },
    _links: { threads: { href: "https://dev.azure.com/contoso/x/_apis/git/repositories/r/pullRequests/12/threads/77" } },
    ...over,
  });
  const replies = () => api.post.mock.calls.filter((c) => /threads\/77\/comments$/.test(String(c[1]))).map((c) => c[2] as { content: string; parentCommentId: number });

  it("finds the thread id from the comment's links", () => {
    expect(threadIdOf(comment("x"))).toBe(77);
    expect(threadIdOf({ _links: { self: { href: "…/threads/5/comments/1" } } })).toBe(5);
    expect(threadIdOf({})).toBeNull();
  });

  it("ignores Pepper's own and system comments", async () => {
    expect((await handleAzureComment(project, comment(`${AZURE_BOT_MARKER}\n@pepper review`), pr(), defer)).message).toMatch(/Ignored/);
    expect((await handleAzureComment(project, comment("@pepper review", { commentType: "system" }), pr(), defer)).message).toMatch(/Ignored/);
    expect((await handleAzureComment(project, comment("looks good"), pr(), defer)).message).toBe("No command");
  });

  it("replies in the thread, marked as Pepper's, and pauses", async () => {
    await handleAzureComment(project, comment("@pepper pause"), pr(), defer);
    expect(db.prReviewState.upsert.mock.calls[0][0]).toMatchObject({ create: { projectId: "p1", prNumber: 12, paused: true, pausedBy: "Alice" } });
    expect(replies()[0]).toMatchObject({ parentCommentId: 3, content: expect.stringContaining(AZURE_BOT_MARKER) });
  });

  it("queues a review after the response", async () => {
    api.get.mockImplementation(async (_a: unknown, path: string) => (String(path).endsWith("/pullRequests/12") ? { ok: true, status: 200, data: pr({ lastMergeSourceCommit: { commitId: "head9" } }) } : notFound));
    await handleAzureComment(project, comment("@pepper review"), pr(), defer);
    expect(queue).not.toHaveBeenCalled();
    await run();
    expect(queue.mock.calls[0][0]).toMatchObject({ commitSha: "head9", scanType: "INCREMENTAL" });
  });

  it("@pepper fix starts a remediation run for the finding in a Pepper thread, and refuses forks", async () => {
    const finding = { id: "f1", title: "SQL injection", description: "d", severity: "HIGH", filePath: "src/a.cs", startLine: 9, ruleId: "r", cweId: "CWE-89" };
    api.get.mockImplementation(async (_a: unknown, path: string) => (String(path).endsWith("/threads/77") ? { ok: true, status: 200, data: { comments: [{ content: `${buildFindingMarker(finding)}\n**SQL injection**` }] } } : notFound));
    db.scan.findFirst.mockResolvedValue({ id: "scan-pr", findings: [finding] });
    remediate.mockResolvedValue({ ok: true, runId: "run1" });
    await handleAzureComment(project, comment("@pepper fix"), pr(), defer);
    await run();
    expect(remediate).toHaveBeenCalledWith({ organizationId: "o1", userId: null, scanId: "scan-pr", findingIds: ["f1"], via: "pr-comment" });
    expect(replies().at(-1)!.content).toMatch(/Working on a fix/);
    expect((await handleAzureComment(project, comment("@pepper fix"), pr({ forkSource: {} }), defer)).message).toMatch(/fork/);
  });
});

describe("Azure DevOps onboarding", () => {
  it("creates the repository with a clone URL built from the connection and names", async () => {
    db.project.findFirst.mockResolvedValue(null);
    expect(await ensureProjectForAzureRepo("o1", { id: "repo-guid", name: "api", defaultBranch: "refs/heads/trunk", project: { name: "Payments" } })).toBe(true);
    expect(create.mock.calls[0][0]).toEqual({ organizationId: "o1", name: "Payments/api", repoUrl: "https://dev.azure.com/contoso/Payments/_git/api", defaultBranch: "trunk" });
    expect(db.project.update.mock.calls[0][0]).toMatchObject({ data: { azureRepoId: "repo-guid", azureProjectName: "Payments", azureRepoName: "api", connectedViaAzure: true } });
  });

  it("refuses incomplete or unsafe identities", async () => {
    expect(await ensureProjectForAzureRepo("o1", { id: "x", name: "a/b", project: { name: "P" } })).toBe(false);
    expect(await ensureProjectForAzureRepo("o1", { name: "api", project: { name: "P" } })).toBe(false);
    expect(create).not.toHaveBeenCalled();
  });
});
