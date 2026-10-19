import { resolveGithubToken, type GithubRepoRef } from "@/lib/github-token-resolve";

export type GithubPrTokenSource = "github_app" | "github_oauth" | "none";

/**
 * Token for opening a fix PR: the GitHub App installation for the repository's
 * owner when one is linked, else the org's GitHub OAuth connection.
 */
export async function resolveGithubPrTokenForOrg(
  organizationId: string,
  repo?: GithubRepoRef | null,
): Promise<{ token: string | undefined; source: GithubPrTokenSource }> {
  const resolved = await resolveGithubToken(organizationId, repo);
  if (resolved?.token.trim()) {
    return { token: resolved.token.trim(), source: resolved.source === "app" ? "github_app" : "github_oauth" };
  }
  return { token: undefined, source: "none" };
}
