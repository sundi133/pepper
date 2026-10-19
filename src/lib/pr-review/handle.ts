/**
 * Pull-request events and `@pepper` commands (docs/PR_REVIEW_BOT_SPEC.md §3–4).
 * The webhook route authenticates the delivery and finds the project; this
 * decides what happens and does it.
 */
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { resolveGithubToken } from "@/lib/github-token-resolve";
import { queueGithubWebhookScan, type GithubWebhookProject } from "@/lib/github-webhook-scan";
import { postPrScanQueuedStatus } from "@/lib/github-pr-comment";
import { postSkippedCommitStatus } from "@/lib/github-pr-status";
import { extractFindingMarkers, buildFindingMarker } from "@/lib/github-pr-inline-format";
import { openGithubSecurityFixPr } from "@/lib/github-open-fix-pr";
import { getLlmConfig } from "@/lib/llm-gateway";
import { githubAppConfig } from "@/lib/github-app";
import { DEFAULT_REPO_CONFIG, type RepoConfig } from "./config";
import { HELP_TEXT, botHandles, commandAuthorization, parsePrCommand } from "./commands";
import { decidePrReview } from "./decision";
import { addReaction, getPullRequest, getReviewComment, loadRepoConfig, postIssueComment, replyToReviewComment, type PullRequestInfo } from "./github";

const log = logger.child({ module: "pr-review" });

type Project = NonNullable<GithubWebhookProject>;

interface PrPayload {
  action?: string;
  number?: number;
  pull_request?: PullRequestInfo & { merged?: boolean };
  repository?: { full_name?: string };
}

const CONFIG_ERROR_MARKER = "<!-- pepper-config-error -->";

async function isPaused(projectId: string, prNumber: number): Promise<boolean> {
  const s = await prisma.prReviewState.findUnique({ where: { projectId_prNumber: { projectId, prNumber } }, select: { paused: true } });
  return Boolean(s?.paused);
}

function repoOf(project: Project): { owner: string; name: string } | null {
  return project.githubOwner && project.githubRepoName ? { owner: project.githubOwner, name: project.githubRepoName } : null;
}

/** Queue a review of the PR's head (incremental or full), fork-aware. */
async function queuePrReview(project: Project, pr: PullRequestInfo, scan: "incremental" | "full", cfg: RepoConfig) {
  const baseFull = pr.base.repo.full_name.toLowerCase();
  const isFork = !pr.head.repo || pr.head.repo.full_name.toLowerCase() !== baseFull;
  return queueGithubWebhookScan({
    project,
    scanType: scan === "full" ? "FULL" : "INCREMENTAL",
    repoUrl: project.repoUrl!,
    // A fork's branch isn't in this repository: clone the base, then fetch the PR ref.
    branch: isFork ? pr.base.ref : pr.head.ref,
    commitSha: pr.head.sha,
    baseSha: pr.base.sha,
    prNumber: pr.number,
    fetchRef: isFork ? `refs/pull/${pr.number}/head` : undefined,
    pathExcludes: cfg.paths.exclude,
  });
}

/** opened / reopened / synchronize / ready_for_review */
export async function handlePullRequestReview(project: Project, payload: PrPayload): Promise<{ message: string; scanId?: string; status?: string }> {
  const pr = payload.pull_request;
  const repo = repoOf(project);
  if (!pr || !repo || !project.repoUrl) return { message: "Event ignored" };

  const resolved = await resolveGithubToken(project.organizationId, repo);
  let cfg = DEFAULT_REPO_CONFIG;
  if (resolved) {
    const loaded = await loadRepoConfig(resolved.token, repo.owner, repo.name, pr.base.ref);
    cfg = loaded.config;
    // Report an invalid .pepper.yaml once, when the PR opens.
    if (loaded.error && (payload.action === "opened" || payload.action === "reopened")) {
      await postIssueComment(resolved.token, repo.owner, repo.name, pr.number, `${CONFIG_ERROR_MARKER}\n⚠️ ${loaded.error}\n\nPepper is using its default settings for this pull request.`).catch(() => undefined);
    }
  }

  const baseFull = pr.base.repo.full_name.toLowerCase();
  const decision = decidePrReview(
    {
      action: payload.action ?? "",
      draft: Boolean(pr.draft),
      baseRef: pr.base.ref,
      author: { login: pr.user?.login ?? "", type: pr.user?.type },
      authorAssociation: pr.author_association ?? null,
      isFork: !pr.head.repo || pr.head.repo.full_name.toLowerCase() !== baseFull,
      paused: await isPaused(project.id, pr.number),
    },
    cfg,
  );
  if (!decision.review) {
    if (decision.status && resolved) {
      await postSkippedCommitStatus({ token: resolved.token, owner: repo.owner, repo: repo.name, sha: pr.head.sha, description: decision.status, state: decision.state });
    }
    log.info({ projectId: project.id, pr: pr.number, reason: decision.reason }, "PR review skipped");
    return { message: `Review skipped: ${decision.reason}` };
  }

  const result = await queuePrReview(project, pr, decision.scan, cfg);
  if (result.status === "QUEUED") await postPrScanQueuedStatus(result.scanId);
  return { message: "Review queued", scanId: result.scanId, status: result.status };
}

// ─── Commands ───────────────────────────────────────────────────────────────

interface CommentPayload {
  action?: string;
  comment?: { id: number; body?: string; author_association?: string; user?: { login?: string; type?: string }; in_reply_to_id?: number };
  issue?: { number: number; pull_request?: unknown };
  pull_request?: { number: number };
}

/**
 * `issue_comment` (on PRs) and `pull_request_review_comment`. Returns quickly;
 * the slow part (scans, fix PRs) runs in `defer`, after the webhook is answered.
 */
export async function handlePrComment(
  project: Project,
  event: "issue_comment" | "pull_request_review_comment",
  payload: CommentPayload,
  defer: (work: () => Promise<void>) => void,
): Promise<{ message: string }> {
  if (payload.action !== "created" || !payload.comment) return { message: "Event ignored" };
  const prNumber = event === "issue_comment" ? (payload.issue?.pull_request ? payload.issue.number : null) : payload.pull_request?.number ?? null;
  if (prNumber == null) return { message: "Not a pull request comment" };

  const command = parsePrCommand(payload.comment.body, botHandles(githubAppConfig()?.slug));
  if (!command) return { message: "No command" };
  const repo = repoOf(project);
  if (!repo) return { message: "Event ignored" };

  const auth = commandAuthorization(payload.comment);
  if (auth === "bot") return { message: "Ignored: bot comment" };
  const resolved = await resolveGithubToken(project.organizationId, repo);
  if (!resolved) return { message: "No GitHub access for this repository" };
  const { token } = resolved;
  const kind = event === "issue_comment" ? "issue" : "review";
  const commentId = payload.comment.id;
  const reply = (body: string) =>
    kind === "review"
      ? replyToReviewComment(token, repo.owner, repo.name, prNumber, commentId, body)
      : postIssueComment(token, repo.owner, repo.name, prNumber, body);

  if (auth === "not-collaborator") {
    await reply("Only repository collaborators can run Pepper commands.").catch(() => undefined);
    return { message: "Refused: not a collaborator" };
  }
  await addReaction(token, repo.owner, repo.name, kind, commentId, "eyes").catch(() => undefined);
  const who = payload.comment.user?.login ?? "someone";

  switch (command) {
    case "help":
    case "unknown":
      await reply(command === "unknown" ? `I didn't understand that.\n\n${HELP_TEXT}` : HELP_TEXT);
      return { message: command };
    case "pause":
    case "resume": {
      const paused = command === "pause";
      await prisma.prReviewState.upsert({
        where: { projectId_prNumber: { projectId: project.id, prNumber } },
        create: { projectId: project.id, prNumber, paused, pausedBy: paused ? who : null },
        update: { paused, pausedBy: paused ? who : null },
      });
      await reply(paused ? `Automatic reviews are paused on this PR (by @${who}). Comment \`@pepper resume\` to restart them.` : "Automatic reviews are back on for this PR.");
      return { message: command };
    }
    case "review":
    case "full-review": {
      defer(async () => {
        const pr = await getPullRequest(token, repo.owner, repo.name, prNumber);
        if (!pr) return;
        const loaded = await loadRepoConfig(token, repo.owner, repo.name, pr.base.ref);
        const result = await queuePrReview(project, pr, command === "full-review" ? "full" : "incremental", loaded.config);
        if (result.status === "QUEUED") await postPrScanQueuedStatus(result.scanId);
      });
      return { message: `${command} queued` };
    }
    case "fix": {
      if (kind !== "review" || !payload.comment.in_reply_to_id) {
        await reply("Reply `@pepper fix` to one of Pepper's inline comments to fix that finding.");
        return { message: "fix needs an inline comment" };
      }
      const parentId = payload.comment.in_reply_to_id;
      defer(async () => {
        const text = await openFixForInlineComment(project, token, repo, prNumber, parentId, who);
        await reply(text).catch(() => undefined);
      });
      return { message: "fix queued" };
    }
  }
}

/** `@pepper fix` in reply to a Pepper inline comment: a fix PR into the PR's branch. */
async function openFixForInlineComment(project: Project, token: string, repo: { owner: string; name: string }, prNumber: number, parentId: number, who: string): Promise<string> {
  const parent = await getReviewComment(token, repo.owner, repo.name, parentId);
  const marker = extractFindingMarkers(parent?.body)[0];
  if (!marker) return "That comment isn't a Pepper finding. Reply `@pepper fix` to one of Pepper's inline comments.";
  const pr = await getPullRequest(token, repo.owner, repo.name, prNumber);
  if (!pr) return "Couldn't read this pull request.";
  if (!pr.head.repo || pr.head.repo.full_name.toLowerCase() !== pr.base.repo.full_name.toLowerCase()) {
    return "Pepper can't push a fix branch to a fork. Apply the fix described above in the fork.";
  }
  const scan = await prisma.scan.findFirst({
    where: { projectId: project.id, prNumber, status: "COMPLETED" },
    orderBy: { completedAt: "desc" },
    select: { id: true, findings: { select: { id: true, title: true, description: true, severity: true, scanner: true, snippet: true, cweId: true, ruleId: true, filePath: true, startLine: true } } },
  });
  const finding = scan?.findings.find((f) => buildFindingMarker(f) === marker);
  if (!finding?.filePath) return "That finding isn't in this PR's latest review any more. Comment `@pepper review` and try again.";
  const settings = await prisma.orgSettings.findUnique({ where: { organizationId: project.organizationId } });
  const llm = getLlmConfig(settings);
  if (!llm.apiKey && llm.provider !== "ollama") return "No AI provider is configured in Pepper, so it can't write a fix.";
  const result = await openGithubSecurityFixPr({
    githubToken: token,
    llm,
    owner: repo.owner,
    repo: repo.name,
    baseBranch: pr.head.ref,
    filePath: finding.filePath,
    finding: { title: finding.title, description: finding.description, severity: finding.severity, scanner: finding.scanner, snippet: finding.snippet, cweId: finding.cweId, ruleId: finding.ruleId },
  });
  log.info({ projectId: project.id, pr: prNumber, findingId: finding.id, by: who, ok: result.ok }, "@pepper fix");
  return result.ok ? `Opened a fix: ${result.pullRequestUrl} (into \`${pr.head.ref}\`).` : `Couldn't open a fix: ${result.error}`;
}
