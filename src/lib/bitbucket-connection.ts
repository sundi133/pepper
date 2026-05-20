import { prisma } from "./prisma";
import { decryptSecret, encryptSecret } from "./token-encryption";
import type { BitbucketAuth } from "./bitbucket-api";

export interface BitbucketConnectionStatus {
  connected: boolean;
  username: string | null;
  workspace: string | null;
  connectedAt: string | null;
}

export async function getBitbucketConnectionStatus(
  organizationId: string,
): Promise<BitbucketConnectionStatus> {
  const row = await prisma.orgBitbucketConnection.findUnique({
    where: { organizationId },
    select: { username: true, workspace: true, createdAt: true },
  });
  if (!row) {
    return { connected: false, username: null, workspace: null, connectedAt: null };
  }
  return {
    connected: true,
    username: row.username,
    workspace: row.workspace,
    connectedAt: row.createdAt.toISOString(),
  };
}

/** Returns decrypted app password + username, or null if not connected. */
export async function getOrgBitbucketAuth(
  organizationId: string,
): Promise<BitbucketAuth | null> {
  const row = await prisma.orgBitbucketConnection.findUnique({
    where: { organizationId },
    select: { username: true, appPasswordEnc: true },
  });
  if (!row?.appPasswordEnc) return null;
  try {
    return {
      username: row.username,
      appPassword: decryptSecret(row.appPasswordEnc),
    };
  } catch {
    return null;
  }
}

export async function saveOrgBitbucketConnection(params: {
  organizationId: string;
  username: string;
  appPassword: string;
  workspace?: string | null;
}): Promise<void> {
  const appPasswordEnc = encryptSecret(params.appPassword);
  await prisma.orgBitbucketConnection.upsert({
    where: { organizationId: params.organizationId },
    create: {
      organizationId: params.organizationId,
      username: params.username,
      appPasswordEnc,
      workspace: params.workspace ?? null,
    },
    update: {
      username: params.username,
      appPasswordEnc,
      workspace: params.workspace ?? null,
    },
  });
}

export async function deleteOrgBitbucketConnection(
  organizationId: string,
): Promise<void> {
  await prisma.orgBitbucketConnection.deleteMany({
    where: { organizationId },
  });
}
