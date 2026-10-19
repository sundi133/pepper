import { NextRequest, NextResponse, after } from "next/server";
import { requireAzureDevOpsWebhookAuth } from "@/lib/webhook-secrets";
import {
  findProjectForAzureDevOpsWebhook,
  isAzureDevOpsPushToDefaultBranch,
  mainBranchWebhookScanType,
  queueAzureDevOpsWebhookScan,
} from "@/lib/azure-devops-webhook-scan";
import {
  ensureProjectForAzureRepo,
  handleAzureComment,
  handleAzurePullRequest,
  type AzureComment,
  type AzurePr,
} from "@/lib/pr-review/azure-devops";
import { logger } from "@/lib/logger";
/**
 * Azure DevOps Services webhooks (Service Hooks).
 *
 * - `git.push` — scan on push to the default branch
 * - `git.pullrequest.created` / `git.pullrequest.updated` — PR reviews, through
 *   the shared review decision (docs/PR_REVIEW_PROVIDERS_SPEC.md §1.4)
 * - `ms.vss-code.git-pullrequest-comment-event` — `@pepper` commands (§1.5)
 *
 * A service hook authenticated with an organization's secret onboards
 * repositories it hasn't seen (one project-level hook covers them all, §1.3).
 *
 * ADO service hooks use Basic auth; verify the password against
 * `AZURE_DEVOPS_WEBHOOK_SECRET` when set.
 */
export async function POST(req: NextRequest) {
  const body = await req.text();

  const authResult = await requireAzureDevOpsWebhookAuth(
    req.headers.get("authorization"),
  );
  if (!authResult.ok) {
    return NextResponse.json({ error: "Invalid auth" }, { status: 401 });
  }

  let payload: AzureWebhookPayload;
  try {
    payload = JSON.parse(body) as AzureWebhookPayload;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const eventType = payload.eventType;
  const resource = payload.resource;
  const isComment = eventType === "ms.vss-code.git-pullrequest-comment-event";
  // Comment events carry the PR (and its repository) under resource.pullRequest.
  const repository = isComment ? resource?.pullRequest?.repository : resource?.repository;
  const repoId = repository?.id;

  if (!repoId) {
    return NextResponse.json({ message: "Missing repository id" });
  }

  let project = await findProjectForAzureDevOpsWebhook(
    repoId,
    authResult.organizationId,
  );
  // Onboard on PR and push events from an organization's own hook (not on
  // comments, and never with the env-only secret, which names no organization).
  if (!project && authResult.organizationId && !isComment) {
    if (await ensureProjectForAzureRepo(authResult.organizationId, repository)) {
      project = await findProjectForAzureDevOpsWebhook(repoId, authResult.organizationId);
    }
  }
  if (!project) {
    return NextResponse.json({ message: "No matching project found" });
  }

  // Always clone from the project's own stored, trusted repoUrl — never the
  // webhook payload's remoteUrl/webUrl, which is attacker-controlled and
  // would otherwise let a forged webhook redirect the org's credentialed
  // clone to an arbitrary host.
  const repoUrl = project.repoUrl;
  if (!repoUrl) {
    return NextResponse.json({ message: "Project has no repo URL configured" });
  }

  if (eventType === "git.push") {
    for (const update of resource?.refUpdates ?? []) {
      const refName = update.name;
      const commitSha = update.newObjectId;
      if (!refName || !commitSha || /^0+$/.test(commitSha)) {
        continue;
      }
      if (
        !isAzureDevOpsPushToDefaultBranch({
          refName,
          defaultBranch: project.defaultBranch,
        })
      ) {
        continue;
      }

      const result = await queueAzureDevOpsWebhookScan({
        project,
        scanType: mainBranchWebhookScanType(),
        repoUrl,
        branch: project.defaultBranch,
        commitSha,
      });
      return NextResponse.json({
        scanId: result.scanId,
        status: result.status,
        trigger: "push_default_branch",
      });
    }
    return NextResponse.json({ message: "Event ignored" });
  }

  if (isComment) {
    if (!resource?.comment || !resource.pullRequest) {
      return NextResponse.json({ message: "Missing comment" });
    }
    const result = await handleAzureComment(project, resource.comment, resource.pullRequest, (work) =>
      after(async () => {
        try {
          await work();
        } catch (err) {
          logger.error({ err }, "Azure DevOps PR command failed");
        }
      }),
    );
    return NextResponse.json(result);
  }

  if (
    eventType !== "git.pullrequest.created" &&
    eventType !== "git.pullrequest.updated"
  ) {
    return NextResponse.json({ message: "Event ignored" });
  }

  if (!resource?.pullRequestId) {
    return NextResponse.json({ message: "Missing pull request" });
  }

  return NextResponse.json(await handleAzurePullRequest(project, eventType, resource as AzurePr));
}

interface AzureWebhookPayload {
  eventType?: string;
  resource?: AzurePr & {
    comment?: AzureComment;
    pullRequest?: AzurePr;
    pullRequestId?: number;
    sourceRefName?: string;
    lastMergeSourceCommit?: { commitId?: string };
    lastMergeTargetCommit?: { commitId?: string };
    refUpdates?: Array<{ name?: string; newObjectId?: string }>;
    repository?: {
      id?: string;
      name?: string;
      remoteUrl?: string;
      webUrl?: string;
    };
  };
}

