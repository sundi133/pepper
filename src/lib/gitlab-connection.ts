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
  /** "personal" or "bot" (group/project access token or service account). */
  tokenKind?: string | null;
  tokenScopes?: string[];
  tokenExpiresAt?: string | null;
  commitStatuses?: boolean;
}

export async function getGitLabConnectionStatus(
  organizationId: string,
): Promise<GitLabConnectionStatus> {
  const row = await prisma.orgGitLabConnection.findUnique({
    where: { organizationId },
    select: { gitlabUsername: true, hostUrl: true, createdAt: true, tokenKind: true, tokenScopes: true, tokenExpiresAt: true, commitStatuses: true },
  });
  if (!row) {
    return { connected: false, username: null, hostUrl: DEFAULT_GITLAB_HOST, connectedAt: null };
  }
  return {
    connected: true,
    username: row.gitlabUsername,
    hostUrl: row.hostUrl,
    connectedAt: row.createdAt.toISOString(),
    tokenKind: row.tokenKind,
    tokenScopes: row.tokenScopes ? row.tokenScopes.split(",").filter(Boolean) : [],
    tokenExpiresAt: row.tokenExpiresAt?.toISOString() ?? null,
    commitStatuses: row.commitStatuses,
  };
}

/** Whether this organization posts `pepper/security` commit statuses on merge requests. */
export async function gitLabCommitStatusesEnabled(organizationId: string): Promise<boolean> {
  const row = await prisma.orgGitLabConnection.findUnique({ where: { organizationId }, select: { commitStatuses: true } });
  return Boolean(row?.commitStatuses);
}

export async function setGitLabCommitStatuses(organizationId: string, on: boolean): Promise<boolean> {
  const r = await prisma.orgGitLabConnection.updateMany({ where: { organizationId }, data: { commitStatuses: on } });
  return r.count > 0;
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
  /** true for group/project access tokens' bot users and service accounts */
  bot?: boolean;
}

export interface GitLabTokenInfo {
  kind: "personal" | "bot";
  scopes: string[];
  expiresAt: Date | null;
}

/** What kind of token this is, its scopes and expiry (best effort; display only). */
export async function describeGitLabToken(auth: GitLabAuth, user: GitLabUser | null): Promise<GitLabTokenInfo> {
  const self = await gitlabGet<{ scopes?: string[]; expires_at?: string | null }>(auth, "/personal_access_tokens/self").catch(() => null);
  const scopes = self?.ok && Array.isArray(self.data.scopes) ? self.data.scopes.filter((x): x is string => typeof x === "string").slice(0, 20) : [];
  const exp = self?.ok && self.data.expires_at ? new Date(self.data.expires_at) : null;
  return { kind: user?.bot ? "bot" : "personal", scopes, expiresAt: exp && !Number.isNaN(exp.getTime()) ? exp : null };
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
  /** New connections: whether to post commit statuses. Reconnecting keeps the current choice when omitted. */
  commitStatuses?: boolean;
}): Promise<void> {
  const host = (params.hostUrl ?? DEFAULT_GITLAB_HOST).replace(/\/+$/, "");
  const auth: GitLabAuth = { hostUrl: host, accessToken: params.accessToken };
  const user = await verifyGitLabToken(auth);
  const info = await describeGitLabToken(auth, user);
  const tokenFields = { tokenKind: info.kind, tokenScopes: info.scopes.join(","), tokenExpiresAt: info.expiresAt };

  const accessTokenEnc = encryptSecret(params.accessToken);
  await prisma.orgGitLabConnection.upsert({
    where: { organizationId: params.organizationId },
    create: {
      organizationId: params.organizationId,
      hostUrl: host,
      accessTokenEnc,
      gitlabUserId: user?.id ?? null,
      gitlabUsername: user?.username ?? null,
      ...tokenFields,
      commitStatuses: params.commitStatuses ?? false,
    },
    update: {
      hostUrl: host,
      accessTokenEnc,
      gitlabUserId: user?.id ?? null,
      gitlabUsername: user?.username ?? null,
      ...tokenFields,
      ...(params.commitStatuses !== undefined ? { commitStatuses: params.commitStatuses } : {}),
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
