export type RepoProvider = "github" | "bitbucket" | "azure";

export type ConnectedRepoBase = {
  projectId: string;
  name: string;
  fullName: string;
  defaultBranch: string;
  branch: string;
  language: string;
  coverage: string;
  scanStatus: string;
  lastScanAt: string | null;
  findingsCount: number;
  scanId: string | null;
};

export type GithubConnectedRepo = ConnectedRepoBase & {
  provider: "github";
  owner: string;
};

export type BitbucketConnectedRepo = ConnectedRepoBase & {
  provider: "bitbucket";
  workspace: string;
};

export type AzureConnectedRepo = ConnectedRepoBase & {
  provider: "azure";
  azureProject: string;
};

export type UnifiedConnectedRepo =
  | GithubConnectedRepo
  | BitbucketConnectedRepo
  | AzureConnectedRepo;

export type GithubStatus = {
  connected: boolean;
  githubLogin: string | null;
  oauthConfigured: boolean;
};

export type BitbucketStatus = {
  connected: boolean;
  username: string | null;
  workspace: string | null;
};

export type AzureDevOpsStatus = {
  connected: boolean;
  azureOrganization: string | null;
  azureUser: string | null;
};
