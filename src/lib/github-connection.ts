import { prisma } from "@/lib/prisma";
import { decryptSecret, encryptSecret } from "@/lib/token-encryption";
import { githubGet } from "@/lib/github-api";

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

/** Returns decrypted access token or null if not connected / decrypt fails. */
export async function getOrgGithubAccessToken(
  organizationId: string,
): Promise<string | null> {
  const row = await prisma.orgGithubConnection.findUnique({
    where: { organizationId },
    select: { accessTokenEnc: true },
  });
  if (!row?.accessTokenEnc) return null;
  try {
    return decryptSecret(row.accessTokenEnc);
  } catch {
    return null;
  }
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
): Promise<string> {
  const token = await getOrgGithubAccessToken(organizationId);
  if (!token) {
    throw new GithubTokenInvalidError("GitHub is not connected for this organization");
  }
  const ok = await verifyGithubToken(token);
  if (!ok) {
    await deleteOrgGithubConnection(organizationId);
    throw new GithubTokenInvalidError();
  }
  return token;
}
