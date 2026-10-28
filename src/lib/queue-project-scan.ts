import { prisma } from "@/lib/prisma";
import { progressWithScanModules } from "@/lib/scan-progress";
import { scanQueue, type ScanJobData } from "@/lib/queue";
import { cancelActiveScansForProject } from "@/lib/active-project-scans";
import { createScanQueuedNotification } from "@/lib/scan-notifications";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { normalizeScanSelection } from "@/lib/scan-types";

export async function queueProjectScan(params: {
  projectId: string;
  organizationId: string;
  userId: string;
  scanType?: ScanJobData["scanType"];
  /** Combine scanner groups on one scan; see normalizeScanSelection. */
  scanModules?: string[];
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

  await cancelActiveScansForProject(params.projectId);

  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: params.organizationId },
  });

  const branch = params.branch?.trim() || project.defaultBranch || "main";
  const selection = normalizeScanSelection(params.scanType ?? "FULL", params.scanModules);

  const scan = await prisma.scan.create({
    data: {
      projectId: params.projectId,
      scanType: selection.scanType,
      scannerProgress: progressWithScanModules(selection.scanModules),
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
    scanType: selection.scanType,
    scanModules: selection.scanModules,
    repoUrl: project.repoUrl.trim(),
    repoUrlDisplay: project.repoUrl.trim(),
    branch,
    useOrgGithubToken: params.useOrgGithubToken ?? false,
    useOrgBitbucketToken: params.useOrgBitbucketToken ?? false,
    useOrgAzureDevOpsToken: params.useOrgAzureDevOpsToken ?? false,
    orgSettings: buildOrgSettingsForJob(orgSettings, params.organizationId),
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
