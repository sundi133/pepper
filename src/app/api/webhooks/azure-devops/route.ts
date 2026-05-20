import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { scanQueue, ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";

/**
 * Azure DevOps Services PR webhook.
 *
 * Configure as an ADO **Service Hook** with event type
 * `git.pullrequest.created` and/or `git.pullrequest.updated`. ADO
 * service hooks support **Basic authentication** but no HMAC signing —
 * the standard practice is to use a shared secret as the Basic-auth
 * password and verify it matches `AZURE_DEVOPS_WEBHOOK_SECRET` here. If
 * the env var is unset we skip verification (useful for local dev only).
 */
export async function POST(req: NextRequest) {
  const body = await req.text();

  const expected = process.env.AZURE_DEVOPS_WEBHOOK_SECRET;
  if (expected) {
    const got = parseBasicAuthSecret(req.headers.get("authorization"));
    if (got !== expected) {
      return NextResponse.json({ error: "Invalid auth" }, { status: 401 });
    }
  }

  let payload: AzurePrWebhookPayload;
  try {
    payload = JSON.parse(body) as AzurePrWebhookPayload;
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const eventType = payload.eventType;
  if (
    eventType !== "git.pullrequest.created" &&
    eventType !== "git.pullrequest.updated"
  ) {
    return NextResponse.json({ message: "Event ignored" });
  }

  const resource = payload.resource;
  if (!resource?.pullRequestId || !resource.repository) {
    return NextResponse.json({ message: "Missing PR or repository" });
  }

  const repoId = resource.repository.id;
  const repoName = resource.repository.name;
  const projectName = resource.repository.project?.name;
  const adoOrgUrl = resource.repository.project?.url;
  // ADO sometimes returns the org name inside `webUrl`; fall back to
  // matching the project just by repoId.
  const branch = resource.sourceRefName?.replace(/^refs\/heads\//, "") ?? null;
  const headSha = resource.lastMergeSourceCommit?.commitId ?? null;
  const baseSha = resource.lastMergeTargetCommit?.commitId ?? null;
  const prId = resource.pullRequestId;
  const repoUrl =
    resource.repository.webUrl ||
    (adoOrgUrl && projectName && repoName
      ? `${adoOrgUrl.replace(/\/_apis\/projects\/.*$/, "")}/${encodeURIComponent(projectName)}/_git/${encodeURIComponent(repoName)}`
      : null);

  if (!repoId) {
    return NextResponse.json({ message: "Missing repository id" });
  }

  const project = await prisma.project.findFirst({
    where: { azureRepoId: repoId },
    include: {
      buildGate: true,
      organization: { include: { settings: true } },
    },
  });

  if (!project) {
    return NextResponse.json({ message: "No matching project found" });
  }

  const { removeAllScansForProject } = await import(
    "@/lib/remove-project-scans"
  );
  await removeAllScansForProject(project.id);

  const settings = project.organization.settings;

  const scan = await prisma.scan.create({
    data: {
      projectId: project.id,
      scanType: "INCREMENTAL",
      sourceType: "WEBHOOK",
      sourceRef: repoUrl ?? repoId,
      branch,
      commitSha: headSha,
      baseSha,
      prNumber: prId,
      status: "QUEUED",
    },
  });

  const jobData: ScanJobData = {
    scanId: scan.id,
    projectId: project.id,
    sourceType: "GIT_CLONE",
    sourceRef: repoUrl ?? repoId,
    scanType: "INCREMENTAL",
    baseSha: baseSha ?? undefined,
    commitSha: headSha ?? undefined,
    repoUrl: repoUrl ?? undefined,
    branch: branch ?? undefined,
    orgSettings: buildOrgSettingsForJob(settings, project.organizationId),
    dastTargetUrl: project.dastTargetUrl || undefined,
    buildGate: project.buildGate
      ? {
          maxCritical: project.buildGate.maxCritical,
          maxHigh: project.buildGate.maxHigh,
          maxMedium: project.buildGate.maxMedium,
          maxLow: project.buildGate.maxLow,
          failOnNew: project.buildGate.failOnNew,
        }
      : undefined,
  };

  const job = await scanQueue.add("scan", jobData, { jobId: scan.id });

  await prisma.scan.update({
    where: { id: scan.id },
    data: { jobId: job.id },
  });

  return NextResponse.json({ scanId: scan.id, status: "QUEUED" });
}

interface AzurePrWebhookPayload {
  eventType?: string;
  resource?: {
    pullRequestId?: number;
    sourceRefName?: string;
    lastMergeSourceCommit?: { commitId?: string };
    lastMergeTargetCommit?: { commitId?: string };
    repository?: {
      id?: string;
      name?: string;
      webUrl?: string;
      project?: { id?: string; name?: string; url?: string };
    };
  };
}

function parseBasicAuthSecret(header: string | null): string | null {
  if (!header) return null;
  if (!header.toLowerCase().startsWith("basic ")) return null;
  try {
    const decoded = Buffer.from(header.slice(6).trim(), "base64").toString(
      "utf8",
    );
    // Either "user:secret" or just ":secret" — the secret is the part
    // after the first colon.
    const idx = decoded.indexOf(":");
    return idx >= 0 ? decoded.slice(idx + 1) : decoded;
  } catch {
    return null;
  }
}
