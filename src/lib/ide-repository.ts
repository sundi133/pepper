/**
 * Which Pepper repository an IDE workspace belongs to, from its git remote
 * (docs/IDE_EXTENSION_SPEC.md §4.1). Pure: the route loads the organization's
 * repositories and passes them in.
 */
import { normalizeGitRemote, remoteRepoName } from "./git-remote";

export interface RepositoryRow {
  id: string;
  name: string;
  repoUrl: string | null;
  defaultBranch: string;
  githubOwner?: string | null;
  githubRepoName?: string | null;
  bitbucketWorkspace?: string | null;
  bitbucketRepoSlug?: string | null;
  azureOrganization?: string | null;
  azureProjectName?: string | null;
  azureRepoName?: string | null;
  gitlabNamespace?: string | null;
}

export type MatchedBy = "url" | "provider" | "name";

export interface RepositoryMatch {
  repository: RepositoryRow | null;
  matchedBy: MatchedBy | null;
  candidates: RepositoryRow[];
}

/** The remote forms a repository is known by, normalized. */
function providerForms(r: RepositoryRow): string[] {
  const out: string[] = [];
  const add = (s: string | null) => s && out.push(s);
  add(normalizeGitRemote(r.repoUrl));
  if (r.githubOwner && r.githubRepoName) add(normalizeGitRemote(`github.com/${r.githubOwner}/${r.githubRepoName}`));
  if (r.bitbucketWorkspace && r.bitbucketRepoSlug) add(normalizeGitRemote(`bitbucket.org/${r.bitbucketWorkspace}/${r.bitbucketRepoSlug}`));
  if (r.azureOrganization && r.azureProjectName && r.azureRepoName) {
    add(normalizeGitRemote(`https://dev.azure.com/${r.azureOrganization}/${r.azureProjectName}/_git/${r.azureRepoName}`));
  }
  return out;
}

const nameKey = (s: string | null | undefined) => (s || "").trim().toLowerCase().split("/").pop() || "";

export function matchRepository(remote: string | null | undefined, folderName: string | null | undefined, repos: RepositoryRow[], maxCandidates = 20): RepositoryMatch {
  const want = normalizeGitRemote(remote);
  if (want) {
    const byUrl = repos.filter((r) => normalizeGitRemote(r.repoUrl) === want);
    if (byUrl.length === 1) return { repository: byUrl[0], matchedBy: "url", candidates: [] };
    const byProvider = repos.filter((r) => providerForms(r).includes(want));
    if (byProvider.length === 1) return { repository: byProvider[0], matchedBy: "provider", candidates: [] };
    // GitLab stores only the namespace path; the host is whatever the remote says.
    const byGitlab = repos.filter((r) => r.gitlabNamespace && want.endsWith(`/${r.gitlabNamespace.toLowerCase()}`));
    if (byGitlab.length === 1) return { repository: byGitlab[0], matchedBy: "provider", candidates: [] };
    const several = [...new Set([...byUrl, ...byProvider, ...byGitlab])];
    if (several.length > 1) return { repository: null, matchedBy: null, candidates: several.slice(0, maxCandidates) };
  }

  const names = [remoteRepoName(remote), nameKey(folderName)].filter(Boolean) as string[];
  const byName = repos.filter((r) => names.includes(nameKey(r.name)));
  if (byName.length === 1) return { repository: byName[0], matchedBy: "name", candidates: [] };
  if (byName.length > 1) return { repository: null, matchedBy: null, candidates: byName.slice(0, maxCandidates) };

  // Nothing matched: offer the closest names first, then the rest.
  const hint = names[0] ?? "";
  const ranked = [...repos].sort((a, b) => Number(nameKey(b.name).includes(hint) && !!hint) - Number(nameKey(a.name).includes(hint) && !!hint));
  return { repository: null, matchedBy: null, candidates: ranked.slice(0, maxCandidates) };
}
