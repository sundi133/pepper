import { prisma } from "@/lib/prisma";
import { scanQueue, type ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { ensureWebhookScanSlot } from "@/lib/webhook-scan-slot";
import { normalizeBitbucketUuid } from "@/lib/parse-bitbucket-repo-input";
import { mainBranchWebhookScanType } from "@/lib/github-webhook-scan";

export type BitbucketWebhookProject = NonNullable<
  Awaited<ReturnType<typeof findProjectForBitbucketWebhook>>
>;

export async function findProjectForBitbucketWebhook(params: {
  fullName: string;
  repoUuid?: string | null;
}) {
  const slug = params.fullName?.trim();
  if (!slug) return null;

  const repoUuid = params.repoUuid?.trim();
  const normalizedUuid = repoUuid ? normalizeBitbucketUuid(repoUuid) : null;

  return prisma.project.findFirst({
    where: {
      OR: [
        { repoUrl: { contains: slug } },
        ...(normalizedUuid
          ? [{ bitbucketRepoUuid: normalizedUuid }]
          : []),
      ],
    },
    include: {
      buildGate: true,
      organization: { include: { settings: true } },
    },
  });
}

/** True when a push targets the project's default branch (e.g. main). */
export function isBitbucketPushToDefaultBranch(params: {
  branchName: string;
  defaultBranch: string;
}): boolean {
  const branch = params.branchName?.trim();
  if (!branch) return false;
  return branch === (params.defaultBranch?.trim() || "main");
}

export async function queueBitbucketWebhookScan(params: {
  project: BitbucketWebhookProject;
  scanType: ScanJobData["scanType"];
  repoUrl: string;
  branch: string;
  commitSha?: string;
  baseSha?: string;
  prNumber?: number;
}): Promise<{ scanId: string; status: "QUEUED" | "ALREADY_QUEUED" }> {
  const commitSha = params.commitSha?.trim();
  const slot = await ensureWebhookScanSlot({
    projectId: params.project.id,
    commitSha,
    scanType: params.scanType,
  });
  if (slot.status === "ALREADY_QUEUED") {
    return { scanId: slot.scanId, status: "ALREADY_QUEUED" };
  }

  const settings = params.project.organization.settings;

  const scan = await prisma.scan.create({
    data: {
      projectId: params.project.id,
      scanType: params.scanType,
      sourceType: "WEBHOOK",
      sourceRef: params.repoUrl,
      branch: params.branch,
      commitSha: commitSha || undefined,
      baseSha: params.baseSha,
      prNumber: params.prNumber,
      status: "QUEUED",
    },
  });

  const jobData: ScanJobData = {
    scanId: scan.id,
    projectId: params.project.id,
    sourceType: "GIT_CLONE",
    sourceRef: params.repoUrl,
    scanType: params.scanType,
    baseSha: params.baseSha,
    commitSha: commitSha || undefined,
    prNumber: params.prNumber,
    repoUrl: params.repoUrl,
    branch: params.branch,
    useOrgBitbucketToken: params.project.connectedViaBitbucket,
    orgSettings: buildOrgSettingsForJob(
      settings,
      params.project.organizationId,
    ),
    dastTargetUrl: params.project.dastTargetUrl || undefined,
    buildGate: params.project.buildGate
      ? {
          maxCritical: params.project.buildGate.maxCritical,
          maxHigh: params.project.buildGate.maxHigh,
          maxMedium: params.project.buildGate.maxMedium,
          maxLow: params.project.buildGate.maxLow,
          failOnNew: params.project.buildGate.failOnNew,
        }
      : undefined,
  };

  const job = await scanQueue.add("scan", jobData, { jobId: scan.id });
  await prisma.scan.update({
    where: { id: scan.id },
    data: { jobId: job.id },
  });

  return { scanId: scan.id, status: "QUEUED" };
}
export { mainBranchWebhookScanType };

