import { parseGithubRepo } from "./github-source-link";

/** Parse `owner/repo`, `https://github.com/owner/repo`, or clone URLs. */
export function parseGithubRepoInput(
  input: string,
): { owner: string; repo: string } | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  const fromUrl = parseGithubRepo(trimmed);
  if (fromUrl) return fromUrl;

  const slash = trimmed.match(/^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+?)(?:\.git)?\/?$/);
  if (slash) {
    return { owner: slash[1], repo: slash[2] };
  }

  return null;
}

export function githubHttpsCloneUrl(owner: string, repo: string): string {
  return `https://github.com/${owner}/${repo}.git`;
}
