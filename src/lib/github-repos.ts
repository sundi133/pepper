import { githubGet } from "@/lib/github-api";

export type GithubRepoListItem = {
  id: number;
  fullName: string;
  owner: string;
  name: string;
  defaultBranch: string;
  language: string | null;
  private: boolean;
  htmlUrl: string;
  cloneUrl: string;
  updatedAt: string | null;
  alreadyConnected: boolean;
};

type GithubApiRepo = {
  id: number;
  full_name: string;
  name: string;
  owner: { login: string };
  default_branch: string;
  language: string | null;
  private: boolean;
  html_url: string;
  clone_url: string;
  updated_at: string | null;
};

export async function listGithubRepositoriesForUser(
  token: string,
  connectedRepoIds: Set<number>,
): Promise<GithubRepoListItem[]> {
  const items: GithubRepoListItem[] = [];
  let page = 1;
  const perPage = 100;

  while (page <= 10) {
    const res = await githubGet<GithubApiRepo[]>(
      token,
      `/user/repos?per_page=${perPage}&page=${page}&sort=updated&affiliation=owner,collaborator,organization_member`,
    );
    if (!res.ok) {
      const msg =
        (res.data as { message?: string })?.message ||
        `GitHub API error (${res.status})`;
      throw new Error(msg);
    }
    const batch = Array.isArray(res.data) ? res.data : [];
    if (batch.length === 0) break;

    for (const r of batch) {
      if (r.owner?.login && r.name) {
        items.push({
          id: r.id,
          fullName: r.full_name,
          owner: r.owner.login,
          name: r.name,
          defaultBranch: r.default_branch || "main",
          language: r.language ?? null,
          private: Boolean(r.private),
          htmlUrl: r.html_url,
          cloneUrl: r.clone_url,
          updatedAt: r.updated_at ?? null,
          alreadyConnected: connectedRepoIds.has(r.id),
        });
      }
    }

    if (batch.length < perPage) break;
    page += 1;
  }

  return items;
}
