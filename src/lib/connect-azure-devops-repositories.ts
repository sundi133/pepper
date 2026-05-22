import { prisma } from "@/lib/prisma";
import {
  getOrgAzureDevOpsAuthOrThrow,
  AzureDevOpsCredentialsInvalidError,
} from "@/lib/azure-devops-connection";
import { listAzureDevOpsRepositoriesInOrganization } from "@/lib/azure-devops-repos";
import { connectAzureDevOpsRepositoryRecord } from "@/lib/azure-devops-repository-connect";

export type ConnectAzureDevOpsRepoResult = {
  connected: Array<{ projectId: string; fullName: string; scanId: string }>;
  skipped: Array<{ repoId: string; reason: string }>;
};

export async function connectAzureDevOpsRepositories(params: {
  organizationId: string;
  userId: string;
  repoIds: string[];
}): Promise<ConnectAzureDevOpsRepoResult> {
  const auth = await getOrgAzureDevOpsAuthOrThrow(params.organizationId);

  const existing = await prisma.project.findMany({
    where: {
      organizationId: params.organizationId,
      azureRepoId: { not: null },
    },
    select: { azureRepoId: true },
  });
  const connectedIds = new Set(
    existing
      .map((p) => p.azureRepoId)
      .filter((id): id is string => id != null),
  );

  let available;
  try {
    available = await listAzureDevOpsRepositoriesInOrganization(
      auth,
      connectedIds,
    );
  } catch (e) {
    if (e instanceof Error && /401|403/i.test(e.message)) {
      throw new AzureDevOpsCredentialsInvalidError();
    }
    throw e;
  }

  const byId = new Map(available.map((r) => [r.id, r]));
  const connected: ConnectAzureDevOpsRepoResult["connected"] = [];
  const skipped: ConnectAzureDevOpsRepoResult["skipped"] = [];

  for (const rawId of params.repoIds) {
    const repoId = rawId.trim();
    const repo = byId.get(repoId);
    if (!repo) {
      skipped.push({
        repoId,
        reason: "Repository not found or not accessible in this organization",
      });
      continue;
    }
    if (repo.alreadyConnected) {
      skipped.push({ repoId, reason: "Already connected" });
      continue;
    }

    const record = await connectAzureDevOpsRepositoryRecord({
      organizationId: params.organizationId,
      userId: params.userId,
      azureOrganization: repo.azureOrganization,
      azureProjectName: repo.azureProjectName,
      azureRepoId: repo.id,
      azureRepoName: repo.azureRepoName,
      cloneUrl: repo.cloneUrl,
      defaultBranch: repo.defaultBranch,
      connectedViaAzure: true,
      queueInitialScan: true,
    });

    connected.push({
      projectId: record.projectId,
      fullName: record.fullName,
      scanId: record.scanId,
    });
    connectedIds.add(repoId);
  }

  return { connected, skipped };
}
