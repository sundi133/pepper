import { NextRequest, NextResponse, after } from "next/server";
import { requireGitlabWebhookAuth } from "@/lib/webhook-secrets";
import { prisma } from "@/lib/prisma";
import { getOrgGitLabAuth } from "@/lib/gitlab-connection";
import {
  findProjectForGitLabWebhook,
  mainBranchWebhookScanType,
  queueGitLabWebhookScan,
} from "@/lib/gitlab-webhook-scan";
import {
  defaultBranchPush,
  ensureProjectForGitLab,
  handleGitLabMergeRequest,
  handleGitLabNote,
  type GitLabMergeRequestEvent,
  type GitLabNoteEvent,
  type GitLabProjectPayload,
} from "@/lib/pr-review/gitlab";
import { logger } from "@/lib/logger";

/**
 * GitLab webhooks (project or group hooks).
 *
 * - `push`: scan on push to the default branch
 * - `merge_request`: reviews through the shared review decision
 *   (docs/PR_REVIEW_PROVIDERS_SPEC.md §2.5)
 * - `note` on a merge request: `@pepper` commands (§2.6)
 *
 * A hook authenticated with an organization's secret onboards projects it
 * hasn't seen, so one group hook covers the group (§2.4).
 */
export async function POST(req: NextRequest) {
  const token = req.headers.get("x-gitlab-token");
  const authResult = await requireGitlabWebhookAuth(token);
  if (!authResult.ok) {
    return NextResponse.json({ error: "Invalid token" }, { status: 401 });
  }

  let payload: GitLabWebhookPayload;
  try {
    payload = (await req.json()) as GitLabWebhookPayload;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const eventType = payload.object_kind;
  if (eventType !== "merge_request" && eventType !== "push" && eventType !== "note") {
    return NextResponse.json({ message: "Event ignored" });
  }

  const glProject = payload.project;
  const gitlabProjectId = typeof glProject?.id === "number" ? glProject.id : undefined;
  const orgId = authResult.organizationId;
  const connection = orgId ? await getOrgGitLabAuth(orgId) : null;

  let project = await findProjectForGitLabWebhook(gitlabProjectId, glProject?.path_with_namespace, orgId, connection?.hostUrl);
  // Onboard on merge request and push events from an organization's own hook (not
  // on notes, and never with the env-only secret, which names no organization).
  if (!project && orgId && eventType !== "note") {
    if (await ensureProjectForGitLab(orgId, glProject)) {
      project = await findProjectForGitLabWebhook(gitlabProjectId, glProject?.path_with_namespace, orgId, connection?.hostUrl);
    }
  }
  if (!project) {
    return NextResponse.json({ message: "No matching project found" });
  }

  // Always clone from the project's own stored, trusted repoUrl — never the
  // webhook payload's git_http_url, which is attacker-controlled and would
  // otherwise let a forged webhook redirect the clone to an arbitrary host.
  const repoUrl = project.repoUrl;
  if (!repoUrl) {
    return NextResponse.json({ message: "Project has no repo URL configured" });
  }

  // Remember the GitLab project id, so notes, statuses and commands can find it.
  if (gitlabProjectId && !project.gitlabProjectId) {
    await prisma.project.update({
      where: { id: project.id },
      data: { gitlabProjectId, gitlabNamespace: glProject?.path_with_namespace ?? null },
    });
    project = { ...project, gitlabProjectId, gitlabNamespace: glProject?.path_with_namespace ?? null };
  }

  if (eventType === "push") {
    const push = defaultBranchPush(project, payload);
    if (!push) return NextResponse.json({ message: "Event ignored" });
    const result = await queueGitLabWebhookScan({
      project,
      scanType: mainBranchWebhookScanType(),
      repoUrl,
      branch: push.branch,
      commitSha: push.commitSha,
    });
    return NextResponse.json({ scanId: result.scanId, status: result.status, trigger: "push_default_branch" });
  }

  if (eventType === "note") {
    const result = await handleGitLabNote(project, payload as GitLabNoteEvent, (work) =>
      after(async () => {
        try {
          await work();
        } catch (err) {
          logger.error({ err }, "GitLab MR command failed");
        }
      }),
    );
    return NextResponse.json(result);
  }

  return NextResponse.json(await handleGitLabMergeRequest(project, payload as GitLabMergeRequestEvent));
}

type GitLabWebhookPayload = (GitLabMergeRequestEvent | GitLabNoteEvent) & {
  object_kind?: string;
  project?: GitLabProjectPayload;
  ref?: string;
  after?: string;
};
