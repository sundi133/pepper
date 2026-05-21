import { azureGet, parseAzureErrorBody } from "./azure-devops-api";
import type { AzureDevOpsAuth } from "./azure-devops-api";
import { parseAzureDevOpsRef } from "./parse-azure-devops-repo-input";

export type AzureDevOpsRepoListItem = {
  id: string;
  fullName: string;
  azureOrganization: string;
  azureProjectName: string;
  azureRepoName: string;
  name: string;
  defaultBranch: string;
  cloneUrl: string;
  alreadyConnected: boolean;
};

type AzureApiRepo = {
  id?: string;
  name?: string;
  remoteUrl?: string;
  webUrl?: string;
  defaultBranch?: string;
  project?: { name?: string; id?: string };
};

type AzureRepoPage = {
  value?: AzureApiRepo[];
};

export async function listAzureDevOpsRepositoriesInOrganization(
  auth: AzureDevOpsAuth,
  connectedRepoIds: Set<string>,
): Promise<AzureDevOpsRepoListItem[]> {
  const items: AzureDevOpsRepoListItem[] = [];
  let skip = 0;
  const top = 100;

  for (let page = 0; page < 50; page++) {
    const res = await azureGet<AzureRepoPage>(
      auth,
      `/_apis/git/repositories?$top=${top}&$skip=${skip}`,
    );
    if (!res.ok) {
      const detail = parseAzureErrorBody(res.data, res.raw);
      throw new Error(
        detail || `Azure DevOps API error (${res.status}) listing repositories`,
      );
    }

    const batch = res.data?.value ?? [];
    if (batch.length === 0) break;

    for (const r of batch) {
      if (!r.id || !r.name || !r.project?.name) continue;
      const projectName = r.project.name;
      const cloneUrl = r.remoteUrl?.trim() || r.webUrl?.trim() || "";
      if (!cloneUrl) continue;
      items.push({
        id: r.id,
        fullName: `${projectName}/${r.name}`,
        azureOrganization: auth.organization,
        azureProjectName: projectName,
        azureRepoName: r.name,
        name: r.name,
        defaultBranch: parseAzureDevOpsRef(r.defaultBranch),
        cloneUrl,
        alreadyConnected: connectedRepoIds.has(r.id),
      });
    }

    if (batch.length < top) break;
    skip += top;
  }

  return items;
}
