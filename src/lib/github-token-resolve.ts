/**
 * Which GitHub credential to use for an organization and, when known, a
 * repository (docs/GITHUB_APP_SPEC.md §7):
 *   1. a linked, active GitHub App installation for the repository's owner;
 *   2. otherwise the organization's OAuth connection (unchanged behaviour);
 *   3. otherwise, with no repository given, the only installation;
 *   4. otherwise none.
 */
import { prisma } from "@/lib/prisma";
import { decryptSecret } from "@/lib/token-encryption";
import { logger } from "@/lib/logger";
import { forgetInstallationToken, getInstallationToken, githubAppConfig, type GithubAppConfig } from "@/lib/github-app";

export type GithubTokenSource = "app" | "oauth";

export interface ResolvedGithubToken {
  token: string;
  source: GithubTokenSource;
  installationId?: bigint;
}

export interface GithubRepoRef {
  owner: string;
  name?: string;
}

async function oauthToken(organizationId: string): Promise<string | null> {
  const row = await prisma.orgGithubConnection.findUnique({ where: { organizationId }, select: { accessTokenEnc: true } });
  if (!row?.accessTokenEnc) return null;
  try {
    return decryptSecret(row.accessTokenEnc);
  } catch {
    return null;
  }
}

/** A token for the installation; a removed or suspended installation is recorded as such. */
export async function installationToken(cfg: GithubAppConfig, inst: { id: string; installationId: bigint }): Promise<string | null> {
  const res = await getInstallationToken(cfg, inst.installationId);
  if (res.ok) return res.token;
  if (res.reason === "removed") {
    forgetInstallationToken(inst.installationId);
    await prisma.orgGithubAppInstallation.deleteMany({ where: { id: inst.id } }).catch(() => undefined);
    logger.warn({ installationId: String(inst.installationId) }, "GitHub App installation no longer exists; unlinked");
  } else if (res.reason === "suspended") {
    await prisma.orgGithubAppInstallation.updateMany({ where: { id: inst.id }, data: { suspendedAt: new Date() } }).catch(() => undefined);
  }
  return null;
}

export async function resolveGithubToken(organizationId: string, repo?: GithubRepoRef | null): Promise<ResolvedGithubToken | null> {
  const cfg = githubAppConfig();
  const installations = cfg
    ? await prisma.orgGithubAppInstallation.findMany({
        where: { organizationId, suspendedAt: null },
        select: { id: true, installationId: true, accountLogin: true },
        orderBy: { createdAt: "asc" },
      })
    : [];

  if (cfg && repo?.owner) {
    const owner = repo.owner.toLowerCase();
    const inst = installations.find((i) => i.accountLogin.toLowerCase() === owner);
    if (inst) {
      const token = await installationToken(cfg, inst);
      if (token) return { token, source: "app", installationId: inst.installationId };
    }
  }

  const oauth = await oauthToken(organizationId);
  if (oauth?.trim()) return { token: oauth.trim(), source: "oauth" };

  if (cfg && !repo && installations.length === 1) {
    const token = await installationToken(cfg, installations[0]);
    if (token) return { token, source: "app", installationId: installations[0].installationId };
  }
  return null;
}
