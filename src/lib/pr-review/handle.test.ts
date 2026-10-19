import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  prReviewState: { findUnique: vi.fn(), upsert: vi.fn(async (_a: unknown) => ({})) },
  scan: { findFirst: vi.fn() },
  orgSettings: { findUnique: vi.fn(async () => ({})) },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
const resolve = vi.hoisted(() => vi.fn());
vi.mock("@/lib/github-token-resolve", () => ({ resolveGithubToken: (...a: unknown[]) => resolve(...a) }));
const queue = vi.hoisted(() => vi.fn(async (_p: Record<string, unknown>) => ({ scanId: "s1", status: "QUEUED" as const })));
vi.mock("@/lib/github-webhook-scan", () => ({ queueGithubWebhookScan: (p: Record<string, unknown>) => queue(p) }));
const queuedStatus = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock("@/lib/github-pr-comment", () => ({ postPrScanQueuedStatus: queuedStatus }));
const skipped = vi.hoisted(() => vi.fn(async (_i: { description: string; state?: string }) => undefined));
vi.mock("@/lib/github-pr-status", () => ({ postSkippedCommitStatus: (i: { description: string; state?: string }) => skipped(i) }));
const fixPr = vi.hoisted(() => vi.fn());
vi.mock("@/lib/github-open-fix-pr", () => ({ openGithubSecurityFixPr: (...a: unknown[]) => fixPr(...a) }));
vi.mock("@/lib/llm-gateway", () => ({ getLlmConfig: () => ({ provider: "anthropic", apiKey: "k", model: "m", baseUrl: "" }) }));
vi.mock("@/lib/github-app", () => ({ githubAppConfig: () => ({ slug: "pepper-sast-acme" }) }));
const gh = vi.hoisted(() => ({
  getPullRequest: vi.fn(),
  postIssueComment: vi.fn(async (..._a: unknown[]) => ({ ok: true })),
  replyToReviewComment: vi.fn(async (..._a: unknown[]) => ({ ok: true })),
  addReaction: vi.fn(async (..._a: unknown[]) => ({ ok: true })),
  getReviewComment: vi.fn(),
  loadRepoConfig: vi.fn(),
}));
vi.mock("./github", () => gh);

import { handlePrComment, handlePullRequestReview } from "./handle";
import { DEFAULT_REPO_CONFIG, parseRepoConfig } from "./config";
import { buildFindingMarker } from "@/lib/github-pr-inline-format";

const project = { id: "p1", organizationId: "o1", githubOwner: "acme", githubRepoName: "api", repoUrl: "https://github.com/acme/api.git", defaultBranch: "main" } as never;
const pr = (over: Record<string, unknown> = {}) => ({
  number: 7, draft: false, user: { login: "alice", type: "User" }, author_association: "MEMBER",
  head: { ref: "feature", sha: "head1", repo: { full_name: "acme/api" } },
  base: { ref: "main", sha: "base1", repo: { full_name: "acme/api" } },
  ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  resolve.mockResolvedValue({ token: "ghs_app", source: "app" });
  gh.loadRepoConfig.mockResolvedValue({ config: DEFAULT_REPO_CONFIG, error: null, found: false });
  db.prReviewState.findUnique.mockResolvedValue(null);
});

describe("pull request events", () => {
  it("queues an incremental review of the PR head and marks it pending", async () => {
    const r = await handlePullRequestReview(project, { action: "opened", pull_request: pr() as never });
    expect(r).toMatchObject({ message: "Review queued", scanId: "s1" });
    expect(queue.mock.calls[0][0]).toMatchObject({ scanType: "INCREMENTAL", branch: "feature", commitSha: "head1", baseSha: "base1", prNumber: 7, repoUrl: "https://github.com/acme/api.git" });
    expect(queue.mock.calls[0][0].fetchRef).toBeUndefined();
    expect(gh.loadRepoConfig).toHaveBeenCalledWith("ghs_app", "acme", "api", "main"); // the base branch's config
    expect(queuedStatus).toHaveBeenCalledWith("s1");
  });

  it("reviews drafts by default; skips them when configured, with a status that says why, and reviews when marked ready", async () => {
    await handlePullRequestReview(project, { action: "opened", pull_request: pr({ draft: true }) as never });
    expect(queue).toHaveBeenCalledTimes(1);
    queue.mockClear();
    gh.loadRepoConfig.mockResolvedValue({ config: parseRepoConfig("reviews:\n  drafts: false").config, error: null, found: true });
    expect((await handlePullRequestReview(project, { action: "opened", pull_request: pr({ draft: true }) as never })).message).toMatch(/draft/);
    expect(skipped.mock.calls[0][0]).toMatchObject({ sha: "head1", description: expect.stringMatching(/draft/) });
    expect(queue).not.toHaveBeenCalled();
    await handlePullRequestReview(project, { action: "ready_for_review", pull_request: pr() as never });
    expect(queue).toHaveBeenCalledTimes(1);
  });

  it("respects a paused PR", async () => {
    db.prReviewState.findUnique.mockResolvedValue({ paused: true });
    expect((await handlePullRequestReview(project, { action: "synchronize", pull_request: pr() as never })).message).toMatch(/paused/);
    expect(queue).not.toHaveBeenCalled();
  });

  it("leaves an outside contributor's fork PR pending until a collaborator asks", async () => {
    await handlePullRequestReview(project, { action: "opened", pull_request: pr({ author_association: "CONTRIBUTOR", head: { ref: "patch-1", sha: "f1", repo: { full_name: "eve/api" } } }) as never });
    expect(queue).not.toHaveBeenCalled();
    expect(skipped.mock.calls[0][0]).toMatchObject({ sha: "f1", state: "pending" });
  });

  it("reviews a collaborator's fork PR by fetching the PR ref onto the base branch", async () => {
    await handlePullRequestReview(project, { action: "opened", pull_request: pr({ author_association: "COLLABORATOR", head: { ref: "patch-1", sha: "f1", repo: { full_name: "bob/api" } } }) as never });
    expect(queue.mock.calls[0][0]).toMatchObject({ branch: "main", commitSha: "f1", fetchRef: "refs/pull/7/head" });
  });

  it("uses .pepper.yaml (full scan, path exclusions) and reports an invalid file once", async () => {
    gh.loadRepoConfig.mockResolvedValue({ config: parseRepoConfig("reviews:\n  scan: full\npaths:\n  exclude: ['docs/**']").config, error: null, found: true });
    await handlePullRequestReview(project, { action: "opened", pull_request: pr() as never });
    expect(queue.mock.calls[0][0]).toMatchObject({ scanType: "FULL", pathExcludes: ["docs/**"] });
    gh.loadRepoConfig.mockResolvedValue({ config: DEFAULT_REPO_CONFIG, error: ".pepper.yaml: comments.max_inline: too big", found: true });
    await handlePullRequestReview(project, { action: "opened", pull_request: pr() as never });
    expect(gh.postIssueComment.mock.calls[0][4]).toMatch(/max_inline/);
    await handlePullRequestReview(project, { action: "synchronize", pull_request: pr() as never });
    expect(gh.postIssueComment).toHaveBeenCalledTimes(1);
  });
});

describe("@pepper commands", () => {
  const deferred: Array<() => Promise<void>> = [];
  const defer = (w: () => Promise<void>) => void deferred.push(w);
  const runDeferred = async () => {
    while (deferred.length) await deferred.shift()!();
  };
  const issueComment = (body: string, association = "MEMBER", user: Record<string, string> = { login: "alice", type: "User" }) => ({
    action: "created",
    comment: { id: 99, body, author_association: association, user },
    issue: { number: 7, pull_request: {} },
  });

  it("ignores non-commands, bots and comments on issues", async () => {
    expect((await handlePrComment(project, "issue_comment", issueComment("LGTM"), defer)).message).toBe("No command");
    expect((await handlePrComment(project, "issue_comment", issueComment("@pepper review", "MEMBER", { login: "pepper-sast-acme[bot]", type: "Bot" }), defer)).message).toMatch(/bot/);
    expect((await handlePrComment(project, "issue_comment", { ...issueComment("@pepper review"), issue: { number: 3 } }, defer)).message).toMatch(/Not a pull request/);
    expect(gh.addReaction).not.toHaveBeenCalled();
  });

  it("refuses non-collaborators with a reply", async () => {
    expect((await handlePrComment(project, "issue_comment", issueComment("@pepper review", "CONTRIBUTOR"), defer)).message).toMatch(/Refused/);
    expect(gh.postIssueComment.mock.calls[0][4]).toMatch(/Only repository collaborators/);
    expect(deferred).toHaveLength(0);
  });

  it("pauses and resumes, acknowledging with 👀 and a reply", async () => {
    await handlePrComment(project, "issue_comment", issueComment("@pepper pause"), defer);
    expect(gh.addReaction).toHaveBeenCalledWith("ghs_app", "acme", "api", "issue", 99, "eyes");
    expect(db.prReviewState.upsert.mock.calls[0][0]).toMatchObject({ create: { projectId: "p1", prNumber: 7, paused: true, pausedBy: "alice" } });
    await handlePrComment(project, "issue_comment", issueComment("@pepper resume"), defer);
    expect(db.prReviewState.upsert.mock.calls[1][0]).toMatchObject({ update: { paused: false } });
  });

  it("runs review and full review after the response", async () => {
    gh.getPullRequest.mockResolvedValue(pr());
    expect((await handlePrComment(project, "issue_comment", issueComment("@pepper full review"), defer)).message).toBe("full-review queued");
    expect(queue).not.toHaveBeenCalled();
    await runDeferred();
    expect(queue.mock.calls[0][0]).toMatchObject({ scanType: "FULL", prNumber: 7, commitSha: "head1" });
  });

  it("answers help and unknown commands", async () => {
    await handlePrComment(project, "issue_comment", issueComment("@pepper"), defer);
    expect(gh.postIssueComment.mock.calls[0][4]).toMatch(/@pepper full review/);
    await handlePrComment(project, "issue_comment", issueComment("@pepper dance"), defer);
    expect(gh.postIssueComment.mock.calls[1][4]).toMatch(/didn't understand/);
  });

  describe("@pepper fix", () => {
    const finding = { id: "f1", title: "SQL injection", description: "d", severity: "HIGH", scanner: "SAST_LLM", snippet: "q(x)", cweId: "CWE-89", ruleId: "r", filePath: "src/a.ts", startLine: 3 };
    const reviewReply = (body = "@pepper fix") => ({ action: "created", comment: { id: 5, body, author_association: "MEMBER", user: { login: "alice" }, in_reply_to_id: 4 }, pull_request: { number: 7 } });

    it("needs to be a reply to an inline comment", async () => {
      expect((await handlePrComment(project, "issue_comment", issueComment("@pepper fix"), defer)).message).toMatch(/inline/);
    });

    it("opens a fix PR into the PR's branch for the finding in the parent comment", async () => {
      gh.getReviewComment.mockResolvedValue({ id: 4, body: `${buildFindingMarker(finding)}\n**SQL injection**` });
      gh.getPullRequest.mockResolvedValue(pr());
      db.scan.findFirst.mockResolvedValue({ id: "s1", findings: [finding] });
      fixPr.mockResolvedValue({ ok: true, pullRequestUrl: "https://github.com/acme/api/pull/8", branch: "pepper/fix" });
      await handlePrComment(project, "pull_request_review_comment", reviewReply(), defer);
      await runDeferred();
      expect(fixPr.mock.calls[0][0]).toMatchObject({ githubToken: "ghs_app", owner: "acme", repo: "api", baseBranch: "feature", filePath: "src/a.ts", finding: { title: "SQL injection" } });
      expect(gh.replyToReviewComment.mock.calls.at(-1)![5]).toMatch(/pull\/8/);
    });

    it("refuses forks and comments that aren't Pepper findings", async () => {
      gh.getReviewComment.mockResolvedValue({ id: 4, body: "just a human comment" });
      await handlePrComment(project, "pull_request_review_comment", reviewReply(), defer);
      await runDeferred();
      expect(gh.replyToReviewComment.mock.calls.at(-1)![5]).toMatch(/isn't a Pepper finding/);
      gh.getReviewComment.mockResolvedValue({ id: 4, body: buildFindingMarker(finding) });
      gh.getPullRequest.mockResolvedValue(pr({ head: { ref: "patch", sha: "x", repo: { full_name: "bob/api" } } }));
      await handlePrComment(project, "pull_request_review_comment", reviewReply(), defer);
      await runDeferred();
      expect(gh.replyToReviewComment.mock.calls.at(-1)![5]).toMatch(/fork/);
      expect(fixPr).not.toHaveBeenCalled();
    });
  });
});
