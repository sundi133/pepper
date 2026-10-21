import { prisma } from "./prisma";
import { decryptSecret, encryptSecret } from "./token-encryption";
import { gitlabGet, DEFAULT_GITLAB_HOST } from "./gitlab-api";
import type { GitLabAuth } from "./gitlab-api";

export type { GitLabAuth };

export interface GitLabConnectionStatus {
  connected: boolean;
  username: string | null;
  hostUrl: string;
  connectedAt: string | null;
}

export async function getGitLabConnectionStatus(
  organizationId: string,
): Promise<GitLabConnectionStatus> {
  const row = await prisma.orgGitLabConnection.findUnique({
    where: { organizationId },
    select: { gitlabUsername: true, hostUrl: true, createdAt: true },
  });
  if (!row) {
    return { connected: false, username: null, hostUrl: DEFAULT_GITLAB_HOST, connectedAt: null };
  }
  return {
    connected: true,
    username: row.gitlabUsername,
    hostUrl: row.hostUrl,
    connectedAt: row.createdAt.toISOString(),
  };
}

/** Returns decrypted GitLab auth, or null if not connected. */
export async function getOrgGitLabAuth(
  organizationId: string,
): Promise<GitLabAuth | null> {
  const row = await prisma.orgGitLabConnection.findUnique({
    where: { organizationId },
    select: { accessTokenEnc: true, hostUrl: true },
  });
  if (!row?.accessTokenEnc) return null;
  try {
    return {
      hostUrl: row.hostUrl,
      accessToken: decryptSecret(row.accessTokenEnc),
    };
  } catch {
    return null;
  }
}

interface GitLabUser {
  id?: number;
  username?: string;
  name?: string;
}

export async function verifyGitLabToken(auth: GitLabAuth): Promise<GitLabUser | null> {
  const res = await gitlabGet<GitLabUser>(auth, "/user");
  if (!res.ok) return null;
  return res.data;
}

export async function saveOrgGitLabConnection(params: {
  organizationId: string;
  accessToken: string;
  hostUrl?: string;
}): Promise<void> {
  const host = (params.hostUrl ?? DEFAULT_GITLAB_HOST).replace(/\/+$/, "");
  const auth: GitLabAuth = { hostUrl: host, accessToken: params.accessToken };
  const user = await verifyGitLabToken(auth);

  const accessTokenEnc = encryptSecret(params.accessToken);
  await prisma.orgGitLabConnection.upsert({
    where: { organizationId: params.organizationId },
    create: {
      organizationId: params.organizationId,
      hostUrl: host,
      accessTokenEnc,
      gitlabUserId: user?.id ?? null,
      gitlabUsername: user?.username ?? null,
    },
    update: {
      hostUrl: host,
      accessTokenEnc,
      gitlabUserId: user?.id ?? null,
      gitlabUsername: user?.username ?? null,
    },
  });
}

export async function deleteOrgGitLabConnection(
  organizationId: string,
): Promise<void> {
  await prisma.orgGitLabConnection.deleteMany({
    where: { organizationId },
  });
}
