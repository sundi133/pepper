import { prisma } from "@/lib/prisma";
import { scanQueue, type ScanJobData } from "@/lib/queue";
import { removeAllScansForProject } from "@/lib/remove-project-scans";
import { createScanQueuedNotification } from "@/lib/scan-notifications";

export async function queueProjectScan(params: {
  projectId: string;
  organizationId: string;
  userId: string;
  scanType?: ScanJobData["scanType"];
  branch?: string;
  useOrgGithubToken?: boolean;
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
    orgSettings: {
      llmProvider: orgSettings?.llmProvider || "openai",
      llmBaseUrl: orgSettings?.llmBaseUrl || "https://api.openai.com/v1",
      llmModel: orgSettings?.llmModel || "gpt-4o-mini",
      llmApiKey: orgSettings?.llmApiKey || undefined,
      enableLlmSast: orgSettings?.enableLlmSast ?? true,
      enableLlmSecrets: orgSettings?.enableLlmSecrets ?? true,
      osvApiUrl: orgSettings?.osvApiUrl || "https://api.osv.dev",
      vulnDbMode: (orgSettings?.vulnDbMode || "online") as
        | "online"
        | "mirror"
        | "offline",
      orgId: params.organizationId,
    },
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
