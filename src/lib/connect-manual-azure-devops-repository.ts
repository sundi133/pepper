import { prisma } from "@/lib/prisma";
import {
  getOrgAzureDevOpsAuthOrThrow,
  AzureDevOpsCredentialsInvalidError,
} from "@/lib/azure-devops-connection";
import { azureGet, parseAzureErrorBody } from "@/lib/azure-devops-api";
import {
  azureDevOpsHttpsCloneUrl,
  parseAzureDevOpsRef,
  parseAzureDevOpsRepoInput,
} from "@/lib/parse-azure-devops-repo-input";
import { connectAzureDevOpsRepositoryRecord } from "@/lib/azure-devops-repository-connect";

type AzureApiRepo = {
  id?: string;
  name?: string;
  remoteUrl?: string;
  webUrl?: string;
  defaultBranch?: string;
  project?: { name?: string };
};

export async function connectManualAzureDevOpsRepository(params: {
  organizationId: string;
  userId: string;
  repoInput: string;
  branch?: string;
}) {
  const auth = await getOrgAzureDevOpsAuthOrThrow(params.organizationId);
  const parsed = parseAzureDevOpsRepoInput(
    params.repoInput,
    auth.organization,
  );
  if (!parsed) {
    throw new Error(
      "Enter a repository as project/repo or https://dev.azure.com/org/project/_git/repo",
    );
  }

  if (parsed.organization !== auth.organization) {
    throw new Error(
      `Repository organization must match your connected Azure DevOps org (${auth.organization})`,
    );
  }

  const meta = await azureGet<AzureApiRepo>(
    auth,
    `/${encodeURIComponent(parsed.project)}/_apis/git/repositories/${encodeURIComponent(parsed.repo)}`,
  );

  if (!meta.ok) {
    const detail = parseAzureErrorBody(meta.data, meta.raw);
    if (meta.status === 404) {
      throw new Error(
        `Repository ${parsed.project}/${parsed.repo} was not found or your PAT cannot access it.`,
      );
    }
    if (meta.status === 401 || meta.status === 403) {
      throw new AzureDevOpsCredentialsInvalidError(
        detail ||
          "Azure DevOps denied access. Reconnect under Settings → Integrations and try again.",
      );
    }
    throw new Error(detail || "Could not load repository from Azure DevOps");
  }

  const repo = meta.data;
  if (!repo?.id || !repo.name) {
    throw new Error("Unexpected response from Azure DevOps");
  }

  const projectName = repo.project?.name || parsed.project;
  const cloneUrl =
    repo.remoteUrl?.trim() ||
    repo.webUrl?.trim() ||
    azureDevOpsHttpsCloneUrl(
      auth.organization,
      projectName,
      repo.name,
    );

  const existing = await prisma.project.findFirst({
    where: {
      organizationId: params.organizationId,
      OR: [{ azureRepoId: repo.id }, { repoUrl: cloneUrl }],
    },
    select: { id: true },
  });

  const record = await connectAzureDevOpsRepositoryRecord({
    organizationId: params.organizationId,
    userId: params.userId,
    azureOrganization: auth.organization,
    azureProjectName: projectName,
    azureRepoId: repo.id,
    azureRepoName: repo.name,
    cloneUrl,
    defaultBranch: parseAzureDevOpsRef(repo.defaultBranch),
    connectedViaAzure: true,
    branch: params.branch,
    queueInitialScan: !existing,
  });

  return record;
}
