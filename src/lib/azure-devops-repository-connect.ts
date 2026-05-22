import { prisma } from "@/lib/prisma";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";
import { queueProjectScan } from "@/lib/queue-project-scan";
import { azureDevOpsHttpsCloneUrl } from "@/lib/parse-azure-devops-repo-input";

export type ConnectAzureDevOpsRepoRecord = {
  projectId: string;
  fullName: string;
  scanId: string;
  created: boolean;
};

export async function connectAzureDevOpsRepositoryRecord(params: {
  organizationId: string;
  userId: string;
  azureOrganization: string;
  azureProjectName: string;
  azureRepoId: string;
  azureRepoName: string;
  cloneUrl: string;
  defaultBranch: string;
  language?: string | null;
  connectedViaAzure: boolean;
  branch?: string;
  queueInitialScan?: boolean;
}): Promise<ConnectAzureDevOpsRepoRecord> {
  const fullName = `${params.azureProjectName}/${params.azureRepoName}`;
  const cloneUrl =
    params.cloneUrl.trim() ||
    azureDevOpsHttpsCloneUrl(
      params.azureOrganization,
      params.azureProjectName,
      params.azureRepoName,
    );

  const existing = await prisma.project.findFirst({
    where: {
      organizationId: params.organizationId,
      OR: [{ azureRepoId: params.azureRepoId }, { repoUrl: cloneUrl }],
    },
  });

  if (existing) {
    await prisma.project.update({
      where: { id: existing.id },
      data: {
        repoUrl: cloneUrl,
        defaultBranch: params.branch?.trim() || params.defaultBranch,
        azureOrganization: params.azureOrganization,
        azureProjectName: params.azureProjectName,
        azureRepoId: params.azureRepoId,
        azureRepoName: params.azureRepoName,
        primaryLanguage: params.language ?? existing.primaryLanguage,
        connectedViaAzure:
          params.connectedViaAzure || existing.connectedViaAzure,
      },
    });
    let scanId = "";
    if (params.queueInitialScan) {
      const queued = await queueProjectScan({
        projectId: existing.id,
        organizationId: params.organizationId,
        userId: params.userId,
        branch: params.branch?.trim() || params.defaultBranch,
        useOrgAzureDevOpsToken: true,
      });
      scanId = queued.scanId;
    }
    return {
      projectId: existing.id,
      fullName,
      scanId,
      created: false,
    };
  }

  const project = await createProjectWithBuildGate({
    organizationId: params.organizationId,
    name: fullName,
    repoUrl: cloneUrl,
    defaultBranch: params.branch?.trim() || params.defaultBranch,
  });

  await prisma.project.update({
    where: { id: project.id },
    data: {
      azureOrganization: params.azureOrganization,
      azureProjectName: params.azureProjectName,
      azureRepoId: params.azureRepoId,
      azureRepoName: params.azureRepoName,
      primaryLanguage: params.language ?? null,
      connectedViaAzure: params.connectedViaAzure,
    },
  });

  let scanId = "";
  if (params.queueInitialScan !== false) {
    const queued = await queueProjectScan({
      projectId: project.id,
      organizationId: params.organizationId,
      userId: params.userId,
      branch: params.branch?.trim() || params.defaultBranch,
      useOrgAzureDevOpsToken: true,
    });
    scanId = queued.scanId;
  }

  return {
    projectId: project.id,
    fullName,
    scanId,
    created: true,
  };
}
