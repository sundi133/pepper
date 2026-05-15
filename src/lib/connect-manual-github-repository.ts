import {
  getOrgGithubAccessTokenOrThrow,
  GithubTokenInvalidError,
} from "@/lib/github-connection";
import { githubGet } from "@/lib/github-api";
import {
  githubHttpsCloneUrl,
  parseGithubRepoInput,
} from "@/lib/parse-github-repo-input";
import { connectGithubRepositoryRecord } from "@/lib/github-repository-connect";

type GithubRepoApi = {
  id: number;
  full_name: string;
  clone_url: string;
  default_branch: string;
  language: string | null;
  private: boolean;
};

export async function connectManualGithubRepository(params: {
  organizationId: string;
  userId: string;
  repoInput: string;
  branch?: string;
}) {
  const parsed = parseGithubRepoInput(params.repoInput);
  if (!parsed) {
    throw new Error(
      "Enter a GitHub repository as owner/repo or https://github.com/owner/repo",
    );
  }

  const token = await getOrgGithubAccessTokenOrThrow(params.organizationId);

  const meta = await githubGet<GithubRepoApi>(
    token,
    `/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}`,
  );

  if (!meta.ok) {
    const msg = (meta.data as { message?: string })?.message;
    if (meta.status === 404) {
      throw new Error(
        `Repository ${parsed.owner}/${parsed.repo} was not found or your GitHub account cannot access it.`,
      );
    }
    if (meta.status === 401 || meta.status === 403) {
      throw new GithubTokenInvalidError(
        msg || "GitHub denied access. Reconnect GitHub and try again.",
      );
    }
    throw new Error(msg || "Could not load repository from GitHub");
  }

  const repo = meta.data;
  if (!repo?.id || !repo.full_name) {
    throw new Error("Unexpected response from GitHub");
  }

  const [owner, name] = repo.full_name.split("/");
  const record = await connectGithubRepositoryRecord({
    organizationId: params.organizationId,
    userId: params.userId,
    owner: owner || parsed.owner,
    repo: name || parsed.repo,
    githubRepoId: repo.id,
    cloneUrl: repo.clone_url || githubHttpsCloneUrl(parsed.owner, parsed.repo),
    defaultBranch: repo.default_branch || "main",
    language: repo.language ?? null,
    connectedViaGithub: true,
    branch: params.branch,
  });

  return record;
}
