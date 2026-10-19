/**
 * Pull-request reviews on Azure DevOps (docs/PR_REVIEW_PROVIDERS_SPEC.md §1):
 * onboarding from a project-level service hook, the shared review decision,
 * `.pepper.yaml` from the target branch, statuses, and `@pepper` commands in
 * PR comment threads. The webhook route authenticates and finds the project.
 */
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { azureApiBase, azureGet, azurePost, type AzureDevOpsAuth } from "@/lib/azure-devops-api";
import { getOrgAzureDevOpsAuth } from "@/lib/azure-devops-connection";
import { STATUS_CONTEXT_GENRE, STATUS_CONTEXT_NAME } from "@/lib/azure-devops-pr-status";
import { queueAzureDevOpsWebhookScan, type AzureDevOpsWebhookProject } from "@/lib/azure-devops-webhook-scan";
import { parseAzureDevOpsRef } from "@/lib/parse-azure-devops-repo-input";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";
import { buildFindingMarker, extractFindingMarkers } from "@/lib/github-pr-inline-format";
import { startRemediationRun } from "@/lib/remediation/start-run";
import { CONFIG_FILE_NAMES, DEFAULT_REPO_CONFIG, parseRepoConfig, type RepoConfig } from "./config";
import { HELP_TEXT, botHandles, parsePrCommand } from "./commands";
import { decidePrReview } from "./decision";

const log = logger.child({ module: "pr-review-azure" });

/** Marks Pepper's own replies, so they're never read as commands. */
export const AZURE_BOT_MARKER = "<!-- pepper-bot -->";

type Project = AzureDevOpsWebhookProject;

export interface AzurePr {
  pullRequestId?: number;
  status?: string;
  isDraft?: boolean;
  sourceRefName?: string;
  targetRefName?: string;
  lastMergeSourceCommit?: { commitId?: string };
  lastMergeTargetCommit?: { commitId?: string };
  createdBy?: { uniqueName?: string; displayName?: string };
  forkSource?: unknown;
  repository?: AzureRepoPayload;
}

export interface AzureRepoPayload {
  id?: string;
  name?: string;
  defaultBranch?: string;
  project?: { name?: string };
}

const SAFE_NAME = /^[^/\\?#%\x00-\x1f]{1,200}$/;

const repoPath = (p: Project) => `/${encodeURIComponent(p.azureProjectName!)}/_apis/git/repositories/${encodeURIComponent(p.azureRepoId!)}`;

// ─── Onboarding ─────────────────────────────────────────────────────────────

/**
 * A repository with no Pepper project, seen through a webhook authenticated with
 * this organization's secret: create it. The clone URL is built from the
 * connection and the names, never taken from the payload.
 */
export async function ensureProjectForAzureRepo(organizationId: string, repo: AzureRepoPayload | undefined): Promise<boolean> {
  const repoId = repo?.id?.trim();
  const name = repo?.name?.trim();
  const projectName = repo?.project?.name?.trim();
  if (!repoId || !name || !projectName || !SAFE_NAME.test(name) || !SAFE_NAME.test(projectName)) return false;
  const auth = await getOrgAzureDevOpsAuth(organizationId);
  if (!auth) return false;
  const existing = await prisma.project.findFirst({ where: { organizationId, azureRepoId: repoId }, select: { id: true } });
  if (existing) return true;
  const repoUrl = `${azureApiBase(auth)}/${encodeURIComponent(projectName)}/_git/${encodeURIComponent(name)}`;
  const project = await createProjectWithBuildGate({
    organizationId,
    name: `${projectName}/${name}`,
    repoUrl,
    defaultBranch: parseAzureDevOpsRef(repo?.defaultBranch),
  });
  await prisma.project.update({
    where: { id: project.id },
    data: {
      azureOrganization: auth.organization,
      azureProjectName: projectName,
      azureRepoId: repoId,
      azureRepoName: name,
      connectedViaAzure: true,
    },
  });
  log.info({ organizationId, repo: `${projectName}/${name}` }, "Azure DevOps repository onboarded from a service hook");
  return true;
}

// ─── Azure DevOps calls ─────────────────────────────────────────────────────

export async function loadAzureRepoConfig(auth: AzureDevOpsAuth, project: Project, branch: string): Promise<{ config: RepoConfig; error: string | null }> {
  for (const name of CONFIG_FILE_NAMES) {
    const q = new URLSearchParams({
      path: `/${name}`,
      "versionDescriptor.version": branch,
      "versionDescriptor.versionType": "branch",
      includeContent: "true",
      $format: "json",
    });
    const r = await azureGet<{ content?: string }>(auth, `${repoPath(project)}/items?${q}`);
    if (r.ok && typeof r.data?.content === "string") return parseRepoConfig(r.data.content);
    if (r.status !== 404) break;
  }
  return { config: DEFAULT_REPO_CONFIG, error: null };
}

export async function postAzureSimpleStatus(auth: AzureDevOpsAuth, project: Project, prId: number, state: "pending" | "succeeded", description: string): Promise<void> {
  const r = await azurePost(auth, `${repoPath(project)}/pullRequests/${prId}/statuses`, {
    state,
    description: description.slice(0, 140),
    context: { name: STATUS_CONTEXT_NAME, genre: STATUS_CONTEXT_GENRE },
  });
  if (!r.ok) log.warn({ prId, status: r.status }, "Azure DevOps PR status failed");
}

async function getPr(auth: AzureDevOpsAuth, project: Project, prId: number): Promise<AzurePr | null> {
  const r = await azureGet<AzurePr>(auth, `${repoPath(project)}/pullRequests/${prId}`);
  return r.ok ? r.data : null;
}

async function replyInThread(auth: AzureDevOpsAuth, project: Project, prId: number, threadId: number, parentCommentId: number, text: string) {
  return azurePost(auth, `${repoPath(project)}/pullRequests/${prId}/threads/${threadId}/comments`, {
    content: `${AZURE_BOT_MARKER}\n${text}`,
    parentCommentId,
    commentType: 1,
  });
}

// ─── Pull requests ──────────────────────────────────────────────────────────

const headOf = (pr: AzurePr) => pr.lastMergeSourceCommit?.commitId ?? null;

async function queueReview(project: Project, pr: AzurePr, scan: "incremental" | "full", cfg: RepoConfig) {
  const isFork = Boolean(pr.forkSource);
  return queueAzureDevOpsWebhookScan({
    project,
    scanType: scan === "full" ? "FULL" : "INCREMENTAL",
    repoUrl: project.repoUrl!,
    // A fork's source branch isn't in this repository: clone the target, then fetch the PR's merge ref.
    branch: isFork ? parseAzureDevOpsRef(pr.targetRefName) : parseAzureDevOpsRef(pr.sourceRefName),
    commitSha: headOf(pr) ?? undefined,
    baseSha: pr.lastMergeTargetCommit?.commitId ?? undefined,
    prNumber: pr.pullRequestId,
    fetchRef: isFork ? `refs/pull/${pr.pullRequestId}/merge` : undefined,
    pathExcludes: cfg.paths.exclude,
  });
}

/** git.pullrequest.created / git.pullrequest.updated */
export async function handleAzurePullRequest(project: Project, eventType: string, pr: AzurePr): Promise<{ message: string; scanId?: string; status?: string }> {
  const prId = pr.pullRequestId;
  if (!prId || !project.repoUrl || !project.azureProjectName || !project.azureRepoId) return { message: "Missing pull request" };
  if (pr.status && pr.status !== "active") return { message: `Event ignored (PR ${pr.status})` };
  const head = headOf(pr);

  // `updated` fires for votes, reviewers, titles…: review only code not reviewed yet.
  if (eventType === "git.pullrequest.updated" && head) {
    const seen = await prisma.scan.findFirst({
      where: { projectId: project.id, prNumber: prId, commitSha: head, status: { in: ["QUEUED", "RUNNING", "COMPLETED"] } },
      select: { id: true },
    });
    if (seen) return { message: "Event ignored (commit already reviewed)" };
  }

  const auth = await getOrgAzureDevOpsAuth(project.organizationId);
  const targetBranch = parseAzureDevOpsRef(pr.targetRefName);
  const cfg = auth ? (await loadAzureRepoConfig(auth, project, targetBranch)).config : DEFAULT_REPO_CONFIG;
  const paused = Boolean((await prisma.prReviewState.findUnique({ where: { projectId_prNumber: { projectId: project.id, prNumber: prId } }, select: { paused: true } }))?.paused);

  const decision = decidePrReview(
    {
      action: eventType === "git.pullrequest.created" ? "opened" : "synchronize",
      draft: Boolean(pr.isDraft),
      baseRef: targetBranch,
      author: { login: pr.createdBy?.uniqueName ?? pr.createdBy?.displayName ?? "" },
      // Opening a PR in Azure DevOps requires access to the repository.
      authorAssociation: "MEMBER",
      isFork: Boolean(pr.forkSource),
      paused,
    },
    cfg,
  );
  if (!decision.review) {
    if (decision.status && auth) await postAzureSimpleStatus(auth, project, prId, decision.state === "pending" ? "pending" : "succeeded", decision.status);
    log.info({ projectId: project.id, prId, reason: decision.reason }, "Azure DevOps PR review skipped");
    return { message: `Review skipped: ${decision.reason}` };
  }

  const result = await queueReview(project, pr, decision.scan, cfg);
  if (result.status === "QUEUED" && auth) await postAzureSimpleStatus(auth, project, prId, "pending", "Pepper: review queued");
  return { message: "Review queued", scanId: result.scanId, status: result.status };
}

// ─── Comment commands ───────────────────────────────────────────────────────

export interface AzureComment {
  id?: number;
  parentCommentId?: number;
  content?: string;
  commentType?: string | number;
  author?: { uniqueName?: string; displayName?: string };
  _links?: { threads?: { href?: string }; self?: { href?: string } };
}

/** The thread id from the comment's links (…/threads/{id} or …/threads/{id}/comments/{c}). */
export function threadIdOf(comment: AzureComment): number | null {
  for (const href of [comment._links?.threads?.href, comment._links?.self?.href]) {
    const m = href ? /\/threads\/(\d+)/.exec(href) : null;
    if (m) return Number(m[1]);
  }
  return null;
}

/** ms.vss-code.git-pullrequest-comment-event */
export async function handleAzureComment(
  project: Project,
  comment: AzureComment,
  pr: AzurePr,
  defer: (work: () => Promise<void>) => void,
): Promise<{ message: string }> {
  const content = comment.content ?? "";
  if (content.includes(AZURE_BOT_MARKER) || content.includes("<!-- pepper-") || String(comment.commentType).toLowerCase() === "system") {
    return { message: "Ignored: Pepper or system comment" };
  }
  const command = parsePrCommand(content, botHandles(null));
  if (!command) return { message: "No command" };
  const prId = pr.pullRequestId;
  const threadId = threadIdOf(comment);
  if (!prId || !threadId || !comment.id || !project.azureProjectName || !project.azureRepoId) return { message: "Missing pull request or thread" };
  const auth = await getOrgAzureDevOpsAuth(project.organizationId);
  if (!auth) return { message: "Azure DevOps is not connected" };
  const commentId = comment.id;
  const reply = (text: string) => replyInThread(auth, project, prId, threadId, commentId, text);
  const who = comment.author?.displayName ?? comment.author?.uniqueName ?? "someone";

  switch (command) {
    case "help":
    case "unknown":
      await reply(command === "unknown" ? `I didn't understand that.\n\n${HELP_TEXT}` : HELP_TEXT);
      return { message: command };
    case "pause":
    case "resume": {
      const paused = command === "pause";
      await prisma.prReviewState.upsert({
        where: { projectId_prNumber: { projectId: project.id, prNumber: prId } },
        create: { projectId: project.id, prNumber: prId, paused, pausedBy: paused ? who : null },
        update: { paused, pausedBy: paused ? who : null },
      });
      await reply(paused ? `Automatic reviews are paused on this PR (by ${who}). Comment \`@pepper resume\` to restart them.` : "Automatic reviews are back on for this PR.");
      return { message: command };
    }
    case "review":
    case "full-review": {
      await reply(command === "full-review" ? "Starting a full review of this PR…" : "Reviewing the latest commit of this PR…");
      defer(async () => {
        const fresh = (await getPr(auth, project, prId)) ?? pr;
        const cfg = (await loadAzureRepoConfig(auth, project, parseAzureDevOpsRef(fresh.targetRefName))).config;
        const result = await queueReview(project, fresh, command === "full-review" ? "full" : "incremental", cfg);
        if (result.status === "QUEUED") await postAzureSimpleStatus(auth, project, prId, "pending", "Pepper: review queued");
      });
      return { message: `${command} queued` };
    }
    case "fix": {
      if (pr.forkSource) {
        await reply("Pepper can't push a fix branch to a fork. Apply the fix described in the thread in the fork.");
        return { message: "fix refused: fork" };
      }
      defer(async () => {
        await reply(await fixFromThread(auth, project, prId, threadId));
      });
      return { message: "fix queued" };
    }
  }
}

/** `@pepper fix` in a Pepper inline thread: a remediation run for that finding, into the PR's branch. */
async function fixFromThread(auth: AzureDevOpsAuth, project: Project, prId: number, threadId: number): Promise<string> {
  const thread = await azureGet<{ comments?: Array<{ content?: string }> }>(auth, `${repoPath(project)}/pullRequests/${prId}/threads/${threadId}`);
  const marker = extractFindingMarkers(thread.data?.comments?.[0]?.content)[0];
  if (!marker) return "Reply `@pepper fix` in one of Pepper's inline threads to fix that finding.";
  const scan = await prisma.scan.findFirst({
    where: { projectId: project.id, prNumber: prId, status: "COMPLETED" },
    orderBy: { completedAt: "desc" },
    select: { id: true, findings: { select: { id: true, title: true, description: true, severity: true, filePath: true, startLine: true, ruleId: true, cweId: true } } },
  });
  const finding = scan?.findings.find((f) => buildFindingMarker(f) === marker);
  if (!scan || !finding) return "That finding isn't in this PR's latest review any more. Comment `@pepper review` and try again.";
  const run = await startRemediationRun({ organizationId: project.organizationId, userId: null, scanId: scan.id, findingIds: [finding.id], via: "pr-comment" });
  if (!run.ok) return `Couldn't start a fix: ${run.error}`;
  const base = process.env.NEXTAUTH_URL?.replace(/\/+$/, "");
  return `Working on a fix${base ? ` ([follow it in Pepper](${base}/scans/${scan.id}))` : ""}. Its pull request into this PR's branch will appear here when it's ready.`;
}
