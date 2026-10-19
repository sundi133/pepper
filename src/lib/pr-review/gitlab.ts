/**
 * Merge-request reviews on GitLab (docs/PR_REVIEW_PROVIDERS_SPEC.md §2):
 * onboarding from a group or project webhook, the shared review decision,
 * `.pepper.yaml` from the target branch, commit statuses, and `@pepper`
 * commands in merge-request notes. The webhook route authenticates and finds
 * the project.
 */
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { gitlabGet, gitlabPost, isOnGitLabHost, type GitLabAuth } from "@/lib/gitlab-api";
import { getOrgGitLabAuth } from "@/lib/gitlab-connection";
import { postGitLabCommitStatus } from "@/lib/gitlab-commit-status";
import { queueGitLabWebhookScan, type GitLabWebhookProject } from "@/lib/gitlab-webhook-scan";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";
import { CONFIG_FILE_NAMES, DEFAULT_REPO_CONFIG, parseRepoConfig, type RepoConfig } from "./config";
import { HELP_TEXT, botHandles, parsePrCommand } from "./commands";
import { decidePrReview } from "./decision";
import { fixForInlineComment, isPrPaused, setPrPaused } from "./shared";

const log = logger.child({ module: "pr-review-gitlab" });

/** Marks Pepper's own notes, so they're never read as commands. */
export const GITLAB_BOT_MARKER = "<!-- pepper-bot -->";

/** GitLab access level for Developer: can push branches, so can run commands and is a collaborator. */
const DEVELOPER = 30;

/** Bot users behind group/project access tokens (`project_123_bot_…`, `group_45_bot`). */
const GITLAB_BOT_USER = /^(?:project|group)_\d+_bot(?:_[0-9a-f]+)?$/i;

type Project = GitLabWebhookProject;

export interface GitLabUserPayload {
  id?: number;
  username?: string;
  name?: string;
}

export interface GitLabProjectPayload {
  id?: number;
  path_with_namespace?: string;
  default_branch?: string;
}

/** `object_attributes` of a merge_request event, or a merge request from the API. */
export interface GitLabMergeRequest {
  iid?: number;
  action?: string;
  state?: string;
  draft?: boolean;
  work_in_progress?: boolean;
  source_branch?: string;
  target_branch?: string;
  source_project_id?: number;
  target_project_id?: number;
  author_id?: number;
  author?: { id?: number; username?: string };
  /** event: the new head; API: `sha` */
  last_commit?: { id?: string };
  sha?: string;
  /** event: set on `update` when commits were pushed */
  oldrev?: string;
  diff_refs?: { base_sha?: string; head_sha?: string } | null;
}

export interface GitLabMergeRequestEvent {
  user?: GitLabUserPayload;
  project?: GitLabProjectPayload;
  object_attributes?: GitLabMergeRequest;
  changes?: {
    draft?: { previous?: boolean; current?: boolean };
    work_in_progress?: { previous?: boolean; current?: boolean };
  };
}

const SAFE_PATH = /^[\w.-]+(?:\/[\w.-]+)+$/;
const SAFE_BRANCH = /^[^\s~^:?*[\\\x00-\x1f]{1,250}$/;

// ─── Onboarding ─────────────────────────────────────────────────────────────

/**
 * A GitLab project with no Pepper project, seen through a webhook authenticated
 * with this organization's secret: create it. The clone URL is built from the
 * connection's host and the path, never taken from the payload.
 */
export async function ensureProjectForGitLab(organizationId: string, glProject: GitLabProjectPayload | undefined): Promise<boolean> {
  const id = glProject?.id;
  const path = glProject?.path_with_namespace?.trim();
  if (typeof id !== "number" || !Number.isSafeInteger(id) || id <= 0) return false;
  if (!path || !SAFE_PATH.test(path) || path.split("/").includes("..")) return false;
  const auth = await getOrgGitLabAuth(organizationId);
  if (!auth) return false;
  const existing = await prisma.project.findFirst({ where: { organizationId, gitlabProjectId: id }, select: { id: true } });
  if (existing) return true;
  const branch = glProject?.default_branch?.trim();
  const project = await createProjectWithBuildGate({
    organizationId,
    name: path,
    repoUrl: `${auth.hostUrl.replace(/\/+$/, "")}/${path}.git`,
    defaultBranch: branch && SAFE_BRANCH.test(branch) ? branch : "main",
  });
  await prisma.project.update({
    where: { id: project.id },
    data: { gitlabProjectId: id, gitlabNamespace: path, connectedViaGitlab: true },
  });
  log.info({ organizationId, repo: path }, "GitLab project onboarded from a webhook");
  return true;
}

// ─── GitLab calls ───────────────────────────────────────────────────────────

export async function loadGitLabRepoConfig(auth: GitLabAuth, gitlabProjectId: number, ref: string): Promise<{ config: RepoConfig; error: string | null }> {
  for (const name of CONFIG_FILE_NAMES) {
    const r = await gitlabGet<unknown>(auth, `/projects/${gitlabProjectId}/repository/files/${encodeURIComponent(name)}/raw?ref=${encodeURIComponent(ref)}`);
    if (r.ok) return parseRepoConfig(r.raw);
    if (r.status !== 404) break;
  }
  return { config: DEFAULT_REPO_CONFIG, error: null };
}

/** The user's effective access level on the project (inherited from groups too), or 0. */
export async function gitlabAccessLevel(auth: GitLabAuth, gitlabProjectId: number, userId: number | undefined): Promise<number> {
  if (typeof userId !== "number") return 0;
  const r = await gitlabGet<{ access_level?: number; state?: string }>(auth, `/projects/${gitlabProjectId}/members/all/${userId}`);
  if (!r.ok || (r.data.state && r.data.state !== "active")) return 0;
  return typeof r.data.access_level === "number" ? r.data.access_level : 0;
}

async function getMr(auth: GitLabAuth, gitlabProjectId: number, iid: number): Promise<GitLabMergeRequest | null> {
  const r = await gitlabGet<GitLabMergeRequest>(auth, `/projects/${gitlabProjectId}/merge_requests/${iid}`);
  return r.ok ? r.data : null;
}

// ─── Merge requests ─────────────────────────────────────────────────────────

const headOf = (mr: GitLabMergeRequest) => mr.last_commit?.id ?? mr.sha ?? mr.diff_refs?.head_sha ?? null;
const isDraft = (mr: GitLabMergeRequest) => Boolean(mr.draft ?? mr.work_in_progress);
const isFork = (mr: GitLabMergeRequest) =>
  typeof mr.source_project_id === "number" && typeof mr.target_project_id === "number" && mr.source_project_id !== mr.target_project_id;

/** The shared decision's action for a merge_request event, or null when it doesn't change the code. */
export function reviewActionOf(event: GitLabMergeRequestEvent): string | null {
  const mr = event.object_attributes ?? {};
  switch (mr.action) {
    case "open":
      return "opened";
    case "reopen":
      return "reopened";
    case "update": {
      if (mr.oldrev) return "synchronize";
      const d = event.changes?.draft ?? event.changes?.work_in_progress;
      if (d && d.previous === true && d.current === false) return "ready_for_review";
      return null;
    }
    default:
      return null;
  }
}

async function queueReview(project: Project, auth: GitLabAuth | null, mr: GitLabMergeRequest, scan: "incremental" | "full", cfg: RepoConfig) {
  const fork = isFork(mr);
  // The diff base: the merge request's base commit on the target branch.
  let baseSha = mr.diff_refs?.base_sha;
  if (!baseSha && auth && project.gitlabProjectId && mr.iid) baseSha = (await getMr(auth, project.gitlabProjectId, mr.iid))?.diff_refs?.base_sha;
  return queueGitLabWebhookScan({
    project,
    scanType: scan === "full" ? "FULL" : "INCREMENTAL",
    repoUrl: project.repoUrl!,
    // A fork's source branch isn't in this project: clone the target, then fetch the MR's head ref.
    branch: fork ? mr.target_branch! : mr.source_branch!,
    commitSha: headOf(mr) ?? undefined,
    baseSha: baseSha ?? undefined,
    prNumber: mr.iid,
    fetchRef: fork ? `refs/merge-requests/${mr.iid}/head` : undefined,
    pathExcludes: cfg.paths.exclude,
  });
}

/** The connection's token, when this project is on its host (never sent to another). */
async function authFor(project: Project): Promise<GitLabAuth | null> {
  const auth = await getOrgGitLabAuth(project.organizationId);
  return auth && project.repoUrl && isOnGitLabHost(project.repoUrl, auth) ? auth : null;
}

async function status(project: Project, auth: GitLabAuth | null, sha: string | null, state: "pending" | "success", description: string) {
  if (!auth || !sha || !project.gitlabProjectId) return;
  await postGitLabCommitStatus({ organizationId: project.organizationId, auth, gitlabProjectId: project.gitlabProjectId, sha, state, description });
}

/** merge_request events */
export async function handleGitLabMergeRequest(project: Project, event: GitLabMergeRequestEvent): Promise<{ message: string; scanId?: string; status?: string }> {
  const mr = event.object_attributes ?? {};
  if (!mr.iid || !mr.source_branch || !mr.target_branch || !project.repoUrl) return { message: "Missing merge request" };
  if (mr.state && mr.state !== "opened") return { message: `Event ignored (merge request ${mr.state})` };
  const action = reviewActionOf(event);
  if (!action) return { message: `Event ignored (${mr.action ?? "no action"} without new commits)` };

  const auth = await authFor(project);
  const glId = project.gitlabProjectId;
  const cfg = auth && glId ? (await loadGitLabRepoConfig(auth, glId, mr.target_branch)).config : DEFAULT_REPO_CONFIG;
  const fork = isFork(mr);
  const login = event.user?.username ?? "";
  const decision = decidePrReview(
    {
      action,
      draft: isDraft(mr),
      baseRef: mr.target_branch,
      author: { login, type: GITLAB_BOT_USER.test(login) ? "Bot" : undefined },
      // Pushing a branch to the project takes Developer access; a fork's author is checked.
      authorAssociation: !fork ? "MEMBER" : auth && glId && (await gitlabAccessLevel(auth, glId, mr.author_id)) >= DEVELOPER ? "MEMBER" : "NONE",
      isFork: fork,
      paused: await isPrPaused(project.id, mr.iid),
    },
    cfg,
  );
  if (!decision.review) {
    if (decision.status) await status(project, auth, headOf(mr), decision.state === "pending" ? "pending" : "success", decision.status);
    log.info({ projectId: project.id, iid: mr.iid, reason: decision.reason }, "GitLab merge request review skipped");
    return { message: `Review skipped: ${decision.reason}` };
  }

  const result = await queueReview(project, auth, mr, decision.scan, cfg);
  if (result.status === "QUEUED") await status(project, auth, headOf(mr), "pending", "Pepper: review queued");
  return { message: "Review queued", scanId: result.scanId, status: result.status };
}

/** push events: scan the default branch, as on the other hosts. */
export function defaultBranchPush(project: Project, event: { ref?: string; after?: string }): { branch: string; commitSha: string } | null {
  const branch = project.defaultBranch?.trim() || "main";
  if (event.ref !== `refs/heads/${branch}`) return null;
  if (!event.after || /^0+$/.test(event.after)) return null;
  return { branch, commitSha: event.after };
}

// ─── Note commands ──────────────────────────────────────────────────────────

export interface GitLabNoteEvent {
  user?: GitLabUserPayload;
  project?: GitLabProjectPayload;
  object_attributes?: {
    id?: number;
    note?: string;
    noteable_type?: string;
    system?: boolean;
    discussion_id?: string;
  };
  merge_request?: GitLabMergeRequest;
}

/** note events on merge requests */
export async function handleGitLabNote(
  project: Project,
  event: GitLabNoteEvent,
  defer: (work: () => Promise<void>) => void,
): Promise<{ message: string }> {
  const note = event.object_attributes ?? {};
  if (note.noteable_type !== "MergeRequest") return { message: "Event ignored (not a merge request note)" };
  const body = note.note ?? "";
  const login = event.user?.username ?? "";
  if (note.system || body.includes(GITLAB_BOT_MARKER) || body.includes("<!-- pepper-") || GITLAB_BOT_USER.test(login)) {
    return { message: "Ignored: Pepper, bot or system note" };
  }
  const command = parsePrCommand(body, botHandles(null));
  if (!command) return { message: "No command" };
  const mr = event.merge_request ?? {};
  const iid = mr.iid;
  const glId = project.gitlabProjectId;
  if (!iid || !glId || !note.id || !note.discussion_id) return { message: "Missing merge request or discussion" };
  const auth = await authFor(project);
  if (!auth) return { message: "GitLab is not connected" };

  const discussion = `/projects/${glId}/merge_requests/${iid}/discussions/${encodeURIComponent(note.discussion_id)}`;
  const reply = (text: string) => gitlabPost(auth, `${discussion}/notes`, { body: `${GITLAB_BOT_MARKER}\n${text}` });

  if ((await gitlabAccessLevel(auth, glId, event.user?.id)) < DEVELOPER) {
    await reply("Only project members with Developer access or higher can run Pepper commands.").catch(() => undefined);
    return { message: "Refused: not a collaborator" };
  }
  await gitlabPost(auth, `/projects/${glId}/merge_requests/${iid}/notes/${note.id}/award_emoji`, { name: "eyes" }).catch(() => undefined);
  const who = login || event.user?.name || "someone";

  switch (command) {
    case "help":
    case "unknown":
      await reply(command === "unknown" ? `I didn't understand that.\n\n${HELP_TEXT}` : HELP_TEXT);
      return { message: command };
    case "pause":
    case "resume":
      await reply(await setPrPaused(project.id, iid, command === "pause", who));
      return { message: command };
    case "review":
    case "full-review": {
      await reply(command === "full-review" ? "Starting a full review of this MR…" : "Reviewing the latest commit of this MR…");
      defer(async () => {
        const fresh = (await getMr(auth, glId, iid)) ?? mr;
        const cfg = (await loadGitLabRepoConfig(auth, glId, fresh.target_branch ?? project.defaultBranch)).config;
        const result = await queueReview(project, auth, { ...fresh, iid }, command === "full-review" ? "full" : "incremental", cfg);
        if (result.status === "QUEUED") await status(project, auth, headOf(fresh), "pending", "Pepper: review queued");
      });
      return { message: `${command} queued` };
    }
    case "fix": {
      if (isFork(mr)) {
        await reply("Pepper can't push a fix branch to a fork. Apply the fix described in the thread in the fork.");
        return { message: "fix refused: fork" };
      }
      defer(async () => {
        const d = await gitlabGet<{ notes?: Array<{ body?: string }> }>(auth, discussion);
        await reply(await fixForInlineComment(project, iid, d.ok ? d.data.notes?.[0]?.body : null));
      });
      return { message: "fix queued" };
    }
  }
}
