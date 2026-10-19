/**
 * Repositories an organization can reach on GitHub: the OAuth user's (as
 * before) plus each linked GitHub App installation's. An installation's
 * entry wins over the OAuth one for the same repository, because the App is
 * what Pepper will use for it (docs/GITHUB_APP_SPEC.md §7).
 */
import { prisma } from "@/lib/prisma";
import { githubAppConfig, listInstallationRepositories } from "@/lib/github-app";
import { listGithubRepositoriesForUser, type GithubRepoListItem } from "@/lib/github-repos";
import { getOrgGithubAccessTokenOrThrow, GithubTokenInvalidError } from "@/lib/github-connection";
import { installationToken } from "@/lib/github-token-resolve";

export type AccessibleGithubRepo = GithubRepoListItem & { via: "app" | "oauth" };

export async function listOrgGithubRepositories(organizationId: string, connectedRepoIds: Set<number>): Promise<AccessibleGithubRepo[]> {
  const byId = new Map<number, AccessibleGithubRepo>();
  const cfg = githubAppConfig();
  const installations = cfg
    ? await prisma.orgGithubAppInstallation.findMany({ where: { organizationId, suspendedAt: null }, select: { id: true, installationId: true } })
    : [];
  const hasOauth = (await prisma.orgGithubConnection.count({ where: { organizationId } })) > 0;

  if (hasOauth) {
    try {
      // Only the OAuth token: listing as the person who connected, as before.
      const token = await getOrgGithubAccessTokenOrThrow(organizationId, null);
      let mine: GithubRepoListItem[];
      try {
        mine = await listGithubRepositoriesForUser(token, connectedRepoIds);
      } catch (e) {
        if (e instanceof Error && /401|403|Bad credentials/i.test(e.message)) throw new GithubTokenInvalidError();
        throw e;
      }
      for (const r of mine) byId.set(r.id, { ...r, via: "oauth" });
    } catch (e) {
      // A broken personal connection must not hide the App's repositories.
      if (!(e instanceof GithubTokenInvalidError) || installations.length === 0) throw e;
    }
  }

  for (const inst of installations) {
    const token = await installationToken(cfg!, inst);
    if (!token) continue;
    for (const r of await listInstallationRepositories(token)) {
      const defaultBranch = r.default_branch || "main";
      byId.set(r.id, {
        id: r.id,
        fullName: r.full_name,
        owner: r.owner.login,
        name: r.name,
        defaultBranch,
        branches: [defaultBranch],
        language: r.language ?? null,
        private: Boolean(r.private),
        htmlUrl: r.html_url,
        cloneUrl: r.clone_url,
        updatedAt: r.updated_at ?? null,
        alreadyConnected: connectedRepoIds.has(r.id),
        via: "app",
      });
    }
  }

  if (!hasOauth && installations.length === 0) {
    throw new GithubTokenInvalidError("GitHub is not connected for this organization");
  }
  return [...byId.values()];
}
