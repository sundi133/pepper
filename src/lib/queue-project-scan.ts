import { prisma } from "@/lib/prisma";
import { scanQueue, type ScanJobData } from "@/lib/queue";
import { removeAllScansForProject } from "@/lib/remove-project-scans";
import { createScanQueuedNotification } from "@/lib/scan-notifications";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";

export async function queueProjectScan(params: {
  projectId: string;
  organizationId: string;
  userId: string;
  scanType?: ScanJobData["scanType"];
  branch?: string;
  useOrgGithubToken?: boolean;
  useOrgBitbucketToken?: boolean;
  useOrgAzureDevOpsToken?: boolean;
}): Promise<{ scanId: string }> {
  const project = await prisma.project.findFirst({
    where: { id: params.projectId, organizationId: params.organizationId },
    include: { organization: true, buildGate: true },
  });

  if (!project) {
    throw new Error("Project not found");
  }
  if (!project.repoUrl?.trim()) {
    throw new Error("Project has no repository URL");
  }

  await removeAllScansForProject(params.projectId);

  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: params.organizationId },
  });

  const branch = params.branch?.trim() || project.defaultBranch || "main";

  const scan = await prisma.scan.create({
    data: {
      projectId: params.projectId,
      scanType: params.scanType ?? "FULL",
      branch,
      sourceType: "GIT_CLONE",
      sourceRef: project.repoUrl.trim(),
      triggeredBy: params.userId,
      status: "QUEUED",
    },
  });

  const jobData: ScanJobData = {
    scanId: scan.id,
    projectId: params.projectId,
    sourceType: "GIT_CLONE",
    sourceRef: project.repoUrl.trim(),
    scanType: params.scanType ?? "FULL",
    repoUrl: project.repoUrl.trim(),
    repoUrlDisplay: project.repoUrl.trim(),
    branch,
    useOrgGithubToken: params.useOrgGithubToken ?? false,
    useOrgBitbucketToken: params.useOrgBitbucketToken ?? false,
    useOrgAzureDevOpsToken: params.useOrgAzureDevOpsToken ?? false,
    orgSettings: buildOrgSettingsForJob(orgSettings, params.organizationId),
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

  try {
    await createScanQueuedNotification({
      userId: params.userId,
      organizationId: params.organizationId,
      scanId: scan.id,
      projectName: project.name,
    });
  } catch (e) {
    console.error("Failed to record notification:", e);
  }

  return { scanId: scan.id };
}
