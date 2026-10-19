import { prisma } from "./prisma";
import { decryptSecret, encryptSecret } from "./token-encryption";
import { bitbucketGet } from "./bitbucket-api";
import type { BitbucketAuth, BitbucketAuthType } from "./bitbucket-api";

export class BitbucketCredentialsInvalidError extends Error {
  constructor(message = "Bitbucket credentials are invalid or revoked") {
    super(message);
    this.name = "BitbucketCredentialsInvalidError";
  }
}

export interface BitbucketConnectionStatus {
  connected: boolean;
  username: string | null;
  workspace: string | null;
  connectedAt: string | null;
  authType?: BitbucketAuthType;
}

export async function getBitbucketConnectionStatus(
  organizationId: string,
): Promise<BitbucketConnectionStatus> {
  const row = await prisma.orgBitbucketConnection.findUnique({
    where: { organizationId },
    select: { username: true, workspace: true, createdAt: true, authType: true },
  });
  if (!row) {
    return { connected: false, username: null, workspace: null, connectedAt: null };
  }
  return {
    connected: true,
    username: row.username,
    workspace: row.workspace,
    connectedAt: row.createdAt.toISOString(),
    authType: (row.authType as BitbucketAuthType) ?? "app_password",
  };
}

/** Returns decrypted credentials (a token, or a legacy app password + username), or null if not connected. */
export async function getOrgBitbucketAuth(
  organizationId: string,
): Promise<BitbucketAuth | null> {
  const row = await prisma.orgBitbucketConnection.findUnique({
    where: { organizationId },
    select: { username: true, appPasswordEnc: true, authType: true, tokenEnc: true },
  });
  if (row?.tokenEnc && (row.authType === "access_token" || row.authType === "api_token")) {
    try {
      return { username: row.username, appPassword: "", token: decryptSecret(row.tokenEnc), authType: row.authType };
    } catch {
      return null;
    }
  }
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
      authType: "app_password",
      tokenEnc: null,
    },
  });
}

/** Save (or replace) a connection made with an access token or an API token. */
export async function saveOrgBitbucketTokenConnection(params: {
  organizationId: string;
  authType: "access_token" | "api_token";
  token: string;
  /** Display name of the token's user or bot. */
  username: string;
  workspace: string;
}): Promise<void> {
  const fields = {
    authType: params.authType,
    tokenEnc: encryptSecret(params.token),
    appPasswordEnc: null,
    username: params.username,
    workspace: params.workspace,
  };
  await prisma.orgBitbucketConnection.upsert({
    where: { organizationId: params.organizationId },
    create: { organizationId: params.organizationId, ...fields },
    update: fields,
  });
}

export async function deleteOrgBitbucketConnection(
  organizationId: string,
): Promise<void> {
  await prisma.orgBitbucketConnection.deleteMany({
    where: { organizationId },
  });
}

/**
 * Whether the credentials still work. Access tokens' bots often can't read
 * `/user`, so tokens are checked against the workspace's repositories.
 */
export async function verifyBitbucketAuth(auth: BitbucketAuth, workspace?: string | null): Promise<boolean> {
  if (auth.token && workspace) {
    const res = await bitbucketGet<unknown>(auth, `/repositories/${encodeURIComponent(workspace)}?pagelen=1`);
    return res.ok;
  }
  const res = await bitbucketGet<{ username?: string }>(auth, "/user");
  return res.ok;
}

export async function getOrgBitbucketAuthOrThrow(
  organizationId: string,
): Promise<BitbucketAuth> {
  const auth = await getOrgBitbucketAuth(organizationId);
  if (!auth) {
    throw new BitbucketCredentialsInvalidError(
      "Bitbucket is not connected for this organization",
    );
  }
  const workspace = auth.token
    ? (await prisma.orgBitbucketConnection.findUnique({ where: { organizationId }, select: { workspace: true } }))?.workspace
    : null;
  const ok = await verifyBitbucketAuth(auth, workspace);
  if (!ok) {
    await deleteOrgBitbucketConnection(organizationId);
    throw new BitbucketCredentialsInvalidError();
  }
  return auth;
}
