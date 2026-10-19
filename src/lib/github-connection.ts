import { prisma } from "@/lib/prisma";
import { encryptSecret } from "@/lib/token-encryption";
import { githubGet } from "@/lib/github-api";
import { resolveGithubToken, type GithubRepoRef } from "@/lib/github-token-resolve";

export type GithubConnectionStatus = {
  connected: boolean;
  githubLogin: string | null;
  scope: string | null;
  connectedAt: string | null;
};

export async function getGithubConnectionStatus(
  organizationId: string,
): Promise<GithubConnectionStatus> {
  const row = await prisma.orgGithubConnection.findUnique({
    where: { organizationId },
    select: {
      githubLogin: true,
      scope: true,
      createdAt: true,
    },
  });
  if (!row) {
    return {
      connected: false,
      githubLogin: null,
      scope: null,
      connectedAt: null,
    };
  }
  return {
    connected: true,
    githubLogin: row.githubLogin,
    scope: row.scope,
    connectedAt: row.createdAt.toISOString(),
  };
}

/**
 * A GitHub token for the organization, or null. With `repo`, a linked GitHub
 * App installation for the repository's owner is used first; otherwise the
 * organization's OAuth connection, as before (docs/GITHUB_APP_SPEC.md §7).
 */
export async function getOrgGithubAccessToken(
  organizationId: string,
  repo?: GithubRepoRef | null,
): Promise<string | null> {
  return (await resolveGithubToken(organizationId, repo))?.token ?? null;
}

export async function saveOrgGithubConnection(params: {
  organizationId: string;
  accessToken: string;
  scope?: string;
  githubUserId?: string;
  githubLogin?: string;
  tokenExpiresAt?: Date | null;
}): Promise<void> {
  const accessTokenEnc = encryptSecret(params.accessToken);
  await prisma.orgGithubConnection.upsert({
    where: { organizationId: params.organizationId },
    create: {
      organizationId: params.organizationId,
      accessTokenEnc,
      scope: params.scope ?? null,
      githubUserId: params.githubUserId ?? null,
      githubLogin: params.githubLogin ?? null,
      tokenExpiresAt: params.tokenExpiresAt ?? null,
    },
    update: {
      accessTokenEnc,
      scope: params.scope ?? null,
      githubUserId: params.githubUserId ?? null,
      githubLogin: params.githubLogin ?? null,
      tokenExpiresAt: params.tokenExpiresAt ?? null,
    },
  });
}

export async function deleteOrgGithubConnection(
  organizationId: string,
): Promise<void> {
  await prisma.orgGithubConnection.deleteMany({
    where: { organizationId },
  });
}

/** Returns true if token still works against GitHub API. */
export async function verifyGithubToken(token: string): Promise<boolean> {
  const res = await githubGet<{ login?: string }>(token, "/user");
  return res.ok;
}

export class GithubTokenInvalidError extends Error {
  constructor(message = "GitHub token is invalid or revoked") {
    super(message);
    this.name = "GithubTokenInvalidError";
  }
}

export async function getOrgGithubAccessTokenOrThrow(
  organizationId: string,
  repo?: GithubRepoRef | null,
): Promise<string> {
  const resolved = await resolveGithubToken(organizationId, repo);
  if (!resolved) {
    throw new GithubTokenInvalidError("GitHub is not connected for this organization");
  }
  // App installation tokens are freshly minted (and can't call /user); only
  // the OAuth token is checked, and only a failed OAuth token is removed.
  if (resolved.source === "oauth") {
    const ok = await verifyGithubToken(resolved.token);
    if (!ok) {
      await deleteOrgGithubConnection(organizationId);
      throw new GithubTokenInvalidError();
    }
  }
  return resolved.token;
}
