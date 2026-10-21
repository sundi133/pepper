import { getOrgGithubAccessToken } from "@/lib/github-connection";

export type GithubPrTokenSource = "github_oauth" | "none";

/** Open fix PR uses only the org GitHub OAuth connection (Repositories / Connect flow). */
export async function resolveGithubPrTokenForOrg(
  organizationId: string,
): Promise<{ token: string | undefined; source: GithubPrTokenSource }> {
  const oauth = await getOrgGithubAccessToken(organizationId);
  if (oauth?.trim()) {
    return { token: oauth.trim(), source: "github_oauth" };
  }
  return { token: undefined, source: "none" };
}
