import { prisma } from "@/lib/prisma";
import { scanQueue, type ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { ensureWebhookScanSlot } from "@/lib/webhook-scan-slot";
import { mainBranchWebhookScanType } from "@/lib/github-webhook-scan";
import { parseAzureDevOpsRef } from "@/lib/parse-azure-devops-repo-input";

export type AzureDevOpsWebhookProject = NonNullable<
  Awaited<ReturnType<typeof findProjectForAzureDevOpsWebhook>>
>;

export async function findProjectForAzureDevOpsWebhook(repoId: string) {
  const id = repoId?.trim();
  if (!id) return null;

  return prisma.project.findFirst({
    where: { azureRepoId: id },
    include: {
      buildGate: true,
      organization: { include: { settings: true } },
    },
  });
}

export function isAzureDevOpsPushToDefaultBranch(params: {
  refName: string;
  defaultBranch: string;
}): boolean {
  const branch = parseAzureDevOpsRef(params.refName);
  return branch === (params.defaultBranch?.trim() || "main");
}

export async function queueAzureDevOpsWebhookScan(params: {
  project: AzureDevOpsWebhookProject;
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
    useOrgAzureDevOpsToken: params.project.connectedViaAzure,
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

