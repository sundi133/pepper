import { NextRequest, NextResponse } from "next/server";
import { requireAzureDevOpsWebhookAuth } from "@/lib/webhook-secrets";
import {
  findProjectForAzureDevOpsWebhook,
  isAzureDevOpsPushToDefaultBranch,
  mainBranchWebhookScanType,
  queueAzureDevOpsWebhookScan,
} from "@/lib/azure-devops-webhook-scan";
/**
 * Azure DevOps Services webhooks (Service Hooks).
 *
 * - `git.push` — scan on push to the default branch
 * - `git.pullrequest.created` / `git.pullrequest.updated` — incremental PR scans
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
  const repository = resource?.repository;
  const repoId = repository?.id;

  if (!repoId) {
    return NextResponse.json({ message: "Missing repository id" });
  }

  const project = await findProjectForAzureDevOpsWebhook(repoId);
  if (!project) {
    return NextResponse.json({ message: "No matching project found" });
  }

  const repoUrl =
    repository?.remoteUrl ||
    repository?.webUrl ||
    project.repoUrl ||
    repoId;

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

  if (
    eventType !== "git.pullrequest.created" &&
    eventType !== "git.pullrequest.updated"
  ) {
    return NextResponse.json({ message: "Event ignored" });
  }

  if (!resource?.pullRequestId) {
    return NextResponse.json({ message: "Missing pull request" });
  }

  const branch =
    resource.sourceRefName?.replace(/^refs\/heads\//, "") ??
    project.defaultBranch;
  const headSha = resource.lastMergeSourceCommit?.commitId ?? null;
  const baseSha = resource.lastMergeTargetCommit?.commitId ?? null;

  const result = await queueAzureDevOpsWebhookScan({
    project,
    scanType: "INCREMENTAL",
    repoUrl,
    branch,
    commitSha: headSha ?? undefined,
    baseSha: baseSha ?? undefined,
    prNumber: resource.pullRequestId,
  });

  return NextResponse.json({
    scanId: result.scanId,
    status: result.status,
  });
}

interface AzureWebhookPayload {
  eventType?: string;
  resource?: {
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

