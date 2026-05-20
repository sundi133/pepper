import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { scanQueue, ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import crypto from "crypto";

/**
 * Bitbucket Cloud PR webhook.
 *
 * Trigger this for the `pullrequest:created` and `pullrequest:updated`
 * events. Bitbucket signs the body with the webhook secret using HMAC
 * SHA-256 and puts the digest in `X-Hub-Signature` (format
 * `sha256=<hex>`), matching GitHub's format. If `BITBUCKET_WEBHOOK_SECRET`
 * is unset we skip verification (useful for local dev).
 */
export async function POST(req: NextRequest) {
  const signature = req.headers.get("x-hub-signature");
  const eventKey = req.headers.get("x-event-key");
  const body = await req.text();

  const webhookSecret = process.env.BITBUCKET_WEBHOOK_SECRET;
  if (webhookSecret && signature) {
    const expected = `sha256=${crypto
      .createHmac("sha256", webhookSecret)
      .update(body)
      .digest("hex")}`;
    if (signature !== expected) {
      return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
    }
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(body);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (
    eventKey !== "pullrequest:created" &&
    eventKey !== "pullrequest:updated"
  ) {
    return NextResponse.json({ message: "Event ignored" });
  }

  const repository = payload.repository as
    | { full_name?: string; uuid?: string }
    | undefined;
  const pullRequest = payload.pullrequest as
    | {
        id?: number;
        source?: {
          branch?: { name?: string };
          commit?: { hash?: string };
          repository?: { full_name?: string };
        };
        destination?: {
          branch?: { name?: string };
          commit?: { hash?: string };
        };
      }
    | undefined;

  if (!repository?.full_name || !pullRequest?.id) {
    return NextResponse.json({ message: "Missing repository or PR" });
  }

  const fullName = repository.full_name; // "workspace/repo-slug"
  const branch = pullRequest.source?.branch?.name ?? null;
  const headSha = pullRequest.source?.commit?.hash ?? null;
  const baseSha = pullRequest.destination?.commit?.hash ?? null;
  const prId = pullRequest.id;

  // Repos cloned over HTTPS use this URL shape on Bitbucket Cloud.
  const repoUrl = `https://bitbucket.org/${fullName}.git`;

  const project = await prisma.project.findFirst({
    where: {
      OR: [
        { repoUrl: { contains: fullName } },
        repository.uuid ? { bitbucketRepoUuid: repository.uuid } : { id: "_never_" },
      ],
    },
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
      sourceRef: repoUrl,
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
    sourceRef: repoUrl,
    scanType: "INCREMENTAL",
    baseSha: baseSha ?? undefined,
    commitSha: headSha ?? undefined,
    repoUrl,
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
