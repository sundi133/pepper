/**
 * Pull-request reviews on Bitbucket Cloud (docs/PR_REVIEW_PROVIDERS_SPEC.md §3):
 * onboarding from a workspace webhook, the shared review decision,
 * `.pepper.yaml` from the destination branch, build statuses, and `@pepper`
 * commands in PR comments. The webhook route authenticates and finds the
 * project.
 */
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { bitbucketGet, bitbucketPost, type BitbucketAuth } from "@/lib/bitbucket-api";
import { getOrgBitbucketAuth } from "@/lib/bitbucket-connection";
import { postBitbucketSimpleStatus } from "@/lib/bitbucket-pr-status";
import { queueBitbucketWebhookScan, type BitbucketWebhookProject } from "@/lib/bitbucket-webhook-scan";
import { normalizeBitbucketUuid } from "@/lib/parse-bitbucket-repo-input";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";
import { CONFIG_FILE_NAMES, DEFAULT_REPO_CONFIG, parseRepoConfig, type RepoConfig } from "./config";
import { HELP_TEXT, botHandles, parsePrCommand } from "./commands";
import { decidePrReview } from "./decision";
import { fixForInlineComment, isPrPaused, setPrPaused } from "./shared";

const log = logger.child({ module: "pr-review-bitbucket" });

/** Marks Pepper's own replies, so they're never read as commands. */
export const BITBUCKET_BOT_MARKER = "<!-- pepper-bot -->";

type Project = BitbucketWebhookProject;

/** `workspace/repo-slug`: Bitbucket's own character set. */
const FULL_NAME = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;

export interface BitbucketUserPayload {
  uuid?: string;
  display_name?: string;
  nickname?: string;
  /** "user", "app_user" (access-token bots, apps) or "team" */
  type?: string;
}

export interface BitbucketRepoPayload {
  full_name?: string;
  uuid?: string;
  is_private?: boolean;
}

export interface BitbucketPr {
  id?: number;
  state?: string;
  draft?: boolean;
  author?: BitbucketUserPayload;
  source?: { branch?: { name?: string }; commit?: { hash?: string }; repository?: BitbucketRepoPayload };
  destination?: { branch?: { name?: string }; commit?: { hash?: string }; repository?: BitbucketRepoPayload };
}

export interface BitbucketComment {
  id?: number;
  content?: { raw?: string | null };
  parent?: { id?: number };
  inline?: unknown;
  user?: BitbucketUserPayload;
}

function reviewUrl(project: { id: string }): string | null {
  const base = process.env.NEXTAUTH_URL || process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL;
  return base ? `${base.replace(/\/+$/, "")}/projects/${project.id}` : null;
}

const repoPath = (fullName: string) => {
  const [ws, slug] = fullName.split("/");
  return `/repositories/${encodeURIComponent(ws)}/${encodeURIComponent(slug)}`;
};

// ─── Onboarding ─────────────────────────────────────────────────────────────

/**
 * A repository with no Pepper project, seen through a webhook authenticated
 * with this organization's secret: create it. The clone URL is built from the
 * repository's full name on bitbucket.org.
 */
export async function ensureProjectForBitbucketRepo(organizationId: string, repo: BitbucketRepoPayload | undefined): Promise<boolean> {
  const fullName = repo?.full_name?.trim();
  const uuid = repo?.uuid ? normalizeBitbucketUuid(repo.uuid) : "";
  if (!fullName || !FULL_NAME.test(fullName) || fullName.split("/").includes("..") || !uuid) return false;
  const auth = await getOrgBitbucketAuth(organizationId);
  if (!auth) return false;
  const existing = await prisma.project.findFirst({ where: { organizationId, bitbucketRepoUuid: uuid }, select: { id: true } });
  if (existing) return true;
  const info = await bitbucketGet<{ mainbranch?: { name?: string } }>(auth, repoPath(fullName)).catch(() => null);
  const branch = info?.ok ? info.data.mainbranch?.name?.trim() : undefined;
  const [workspace, slug] = fullName.split("/");
  const project = await createProjectWithBuildGate({
    organizationId,
    name: fullName,
    repoUrl: `https://bitbucket.org/${fullName}.git`,
    defaultBranch: branch && /^[^\s~^:?*[\\\x00-\x1f]{1,250}$/.test(branch) ? branch : "main",
  });
  await prisma.project.update({
    where: { id: project.id },
    data: { bitbucketWorkspace: workspace, bitbucketRepoSlug: slug, bitbucketRepoUuid: uuid, connectedViaBitbucket: true },
  });
  log.info({ organizationId, repo: fullName }, "Bitbucket repository onboarded from a webhook");
  return true;
}

// ─── Bitbucket calls ────────────────────────────────────────────────────────

/** `.pepper.yaml` at the destination's commit (or branch). */
export async function loadBitbucketRepoConfig(auth: BitbucketAuth, fullName: string, ref: string): Promise<{ config: RepoConfig; error: string | null }> {
  for (const name of CONFIG_FILE_NAMES) {
    const r = await bitbucketGet<unknown>(auth, `${repoPath(fullName)}/src/${encodeURIComponent(ref)}/${name}`);
    if (r.ok) return parseRepoConfig(r.raw);
    if (r.status !== 404) break;
  }
  return { config: DEFAULT_REPO_CONFIG, error: null };
}

/**
 * Whether the user has Write or Admin on the repository. Checking needs Admin
 * on the token; null when Bitbucket wouldn't say.
 */
export async function bitbucketCanWrite(auth: BitbucketAuth, fullName: string, userUuid: string | undefined): Promise<boolean | null> {
  if (!userUuid) return null;
  const r = await bitbucketGet<{ permission?: string }>(auth, `${repoPath(fullName)}/permissions-config/users/${encodeURIComponent(userUuid)}`);
  if (!r.ok) return null;
  return r.data.permission === "write" || r.data.permission === "admin";
}

// ─── Pull requests ──────────────────────────────────────────────────────────

const headOf = (pr: BitbucketPr) => pr.source?.commit?.hash ?? null;
const sourceName = (pr: BitbucketPr) => pr.source?.repository?.full_name?.trim() ?? "";
const isFork = (pr: BitbucketPr, fullName: string) => {
  const src = sourceName(pr);
  return Boolean(src) && src.toLowerCase() !== fullName.toLowerCase();
};

async function status(auth: BitbucketAuth | null, project: Project, fullName: string, sha: string | null, state: "INPROGRESS" | "SUCCESSFUL", description: string) {
  if (!auth || !sha) return;
  const [workspace, repoSlug] = fullName.split("/");
  await postBitbucketSimpleStatus({ auth, workspace, repoSlug, sha, state, description, url: reviewUrl(project) });
}

async function queueReview(project: Project, fullName: string, pr: BitbucketPr, scan: "incremental" | "full", cfg: RepoConfig) {
  const fork = isFork(pr, fullName);
  // No PR refs in the destination: a fork's PR is cloned from the fork (on bitbucket.org).
  const src = sourceName(pr);
  return queueBitbucketWebhookScan({
    project,
    scanType: scan === "full" ? "FULL" : "INCREMENTAL",
    repoUrl: `https://bitbucket.org/${fork ? src : fullName}.git`,
    branch: pr.source?.branch?.name ?? project.defaultBranch,
    commitSha: headOf(pr) ?? undefined,
    baseSha: pr.destination?.commit?.hash ?? undefined,
    prNumber: pr.id,
    pathExcludes: cfg.paths.exclude,
  });
}

/** pullrequest:created / pullrequest:updated */
export async function handleBitbucketPullRequest(
  project: Project,
  fullName: string,
  eventKey: string,
  pr: BitbucketPr,
): Promise<{ message: string; scanId?: string; status?: string }> {
  const prId = pr.id;
  if (!prId || !FULL_NAME.test(fullName)) return { message: "Missing pull request" };
  if (pr.state && pr.state !== "OPEN") return { message: `Event ignored (PR ${pr.state.toLowerCase()})` };
  const fork = isFork(pr, fullName);
  if (fork && !FULL_NAME.test(sourceName(pr))) return { message: "Event ignored (unknown fork)" };
  const head = headOf(pr);

  // `updated` fires for titles, descriptions, reviewers…: review only code not reviewed yet.
  if (eventKey === "pullrequest:updated" && head) {
    const seen = await prisma.scan.findFirst({
      where: { projectId: project.id, prNumber: prId, commitSha: head, status: { in: ["QUEUED", "RUNNING", "COMPLETED"] } },
      select: { id: true },
    });
    if (seen) return { message: "Event ignored (commit already reviewed)" };
  }

  const auth = await getOrgBitbucketAuth(project.organizationId);
  const target = pr.destination?.branch?.name ?? project.defaultBranch;
  const cfg = auth ? (await loadBitbucketRepoConfig(auth, fullName, pr.destination?.commit?.hash ?? target)).config : DEFAULT_REPO_CONFIG;
  const author = pr.author ?? {};
  const decision = decidePrReview(
    {
      action: eventKey === "pullrequest:created" ? "opened" : "synchronize",
      draft: Boolean(pr.draft),
      baseRef: target,
      author: { login: author.nickname ?? author.display_name ?? "", type: author.type === "app_user" ? "Bot" : undefined },
      // A branch in the repository takes Write access; a fork's author is checked.
      authorAssociation: !fork ? "MEMBER" : auth && (await bitbucketCanWrite(auth, fullName, author.uuid)) ? "MEMBER" : "NONE",
      isFork: fork,
      paused: await isPrPaused(project.id, prId),
    },
    cfg,
  );
  if (!decision.review) {
    if (decision.status) await status(auth, project, fullName, head, decision.state === "pending" ? "INPROGRESS" : "SUCCESSFUL", decision.status);
    log.info({ projectId: project.id, prId, reason: decision.reason }, "Bitbucket PR review skipped");
    return { message: `Review skipped: ${decision.reason}` };
  }

  const result = await queueReview(project, fullName, pr, decision.scan, cfg);
  if (result.status === "QUEUED") await status(auth, project, fullName, head, "INPROGRESS", "Pepper: review queued");
  return { message: "Review queued", scanId: result.scanId, status: result.status };
}

// ─── Comment commands ───────────────────────────────────────────────────────

/** pullrequest:comment_created */
export async function handleBitbucketComment(
  project: Project,
  fullName: string,
  event: { comment?: BitbucketComment; pullrequest?: BitbucketPr; repository?: BitbucketRepoPayload; actor?: BitbucketUserPayload },
  defer: (work: () => Promise<void>) => void,
): Promise<{ message: string }> {
  const comment = event.comment ?? {};
  const body = comment.content?.raw ?? "";
  if (body.includes(BITBUCKET_BOT_MARKER) || body.includes("<!-- pepper-")) return { message: "Ignored: Pepper comment" };
  const user = comment.user ?? event.actor ?? {};
  if (user.type === "app_user") return { message: "Ignored: bot comment" };
  const command = parsePrCommand(body, botHandles(null));
  if (!command) return { message: "No command" };
  const pr = event.pullrequest ?? {};
  const prId = pr.id;
  if (!prId || !comment.id || !FULL_NAME.test(fullName)) return { message: "Missing pull request or comment" };
  const auth = await getOrgBitbucketAuth(project.organizationId);
  if (!auth) return { message: "Bitbucket is not connected" };

  const commentsPath = `${repoPath(fullName)}/pullrequests/${prId}/comments`;
  const reply = (text: string) => bitbucketPost(auth, commentsPath, { content: { raw: `${BITBUCKET_BOT_MARKER}\n${text}` }, parent: { id: comment.id } });

  // Write or Admin when Bitbucket says; otherwise only on private repositories,
  // where commenting already needs access.
  const canWrite = await bitbucketCanWrite(auth, fullName, user.uuid);
  if (canWrite === false || (canWrite === null && event.repository?.is_private !== true)) {
    await reply("Only people with write access to this repository can run Pepper commands.").catch(() => undefined);
    return { message: "Refused: not a collaborator" };
  }
  const who = user.display_name ?? user.nickname ?? "someone";

  switch (command) {
    case "help":
    case "unknown":
      await reply(command === "unknown" ? `I didn't understand that.\n\n${HELP_TEXT}` : HELP_TEXT);
      return { message: command };
    case "pause":
    case "resume":
      await reply(await setPrPaused(project.id, prId, command === "pause", who));
      return { message: command };
    case "review":
    case "full-review": {
      await reply(command === "full-review" ? "Starting a full review of this PR…" : "Reviewing the latest commit of this PR…");
      defer(async () => {
        const r = await bitbucketGet<BitbucketPr>(auth, `${repoPath(fullName)}/pullrequests/${prId}`);
        const fresh = r.ok ? r.data : pr;
        if (isFork(fresh, fullName) && !FULL_NAME.test(sourceName(fresh))) return;
        const cfg = (await loadBitbucketRepoConfig(auth, fullName, fresh.destination?.commit?.hash ?? fresh.destination?.branch?.name ?? project.defaultBranch)).config;
        const result = await queueReview(project, fullName, { ...fresh, id: prId }, command === "full-review" ? "full" : "incremental", cfg);
        if (result.status === "QUEUED") await status(auth, project, fullName, headOf(fresh), "INPROGRESS", "Pepper: review queued");
      });
      return { message: `${command} queued` };
    }
    case "fix": {
      if (isFork(pr, fullName)) {
        await reply("Pepper can't push a fix branch to a fork. Apply the fix described in the thread in the fork.");
        return { message: "fix refused: fork" };
      }
      defer(async () => {
        const parentId = comment.parent?.id;
        const parent = parentId ? await bitbucketGet<BitbucketComment>(auth, `${commentsPath}/${parentId}`) : null;
        await reply(await fixForInlineComment(project, prId, parent?.ok ? parent.data.content?.raw : null));
      });
      return { message: "fix queued" };
    }
  }
}
