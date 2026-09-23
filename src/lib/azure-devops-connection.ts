import { prisma } from "./prisma";
import { decryptSecret, encryptSecret } from "./token-encryption";
import { azureGet } from "./azure-devops-api";
import type { AzureDevOpsAuth } from "./azure-devops-api";

export class AzureDevOpsCredentialsInvalidError extends Error {
  constructor(message = "Azure DevOps credentials are invalid or revoked") {
    super(message);
    this.name = "AzureDevOpsCredentialsInvalidError";
  }
}

export interface AzureDevOpsConnectionStatus {
  connected: boolean;
  azureOrganization: string | null;
  azureServerUrl: string | null;
  azureUser: string | null;
  connectedAt: string | null;
}

export async function getAzureDevOpsConnectionStatus(
  organizationId: string,
): Promise<AzureDevOpsConnectionStatus> {
  const row = await prisma.orgAzureDevOpsConnection.findUnique({
    where: { organizationId },
    select: {
      azureOrganization: true,
      azureServerUrl: true,
      azureUser: true,
      createdAt: true,
    },
  });
  if (!row) {
    return {
      connected: false,
      azureOrganization: null,
      azureServerUrl: null,
      azureUser: null,
      connectedAt: null,
    };
  }
  return {
    connected: true,
    azureOrganization: row.azureOrganization,
    azureServerUrl: row.azureServerUrl ?? null,
    azureUser: row.azureUser ?? null,
    connectedAt: row.createdAt.toISOString(),
  };
}

/** Decrypts and returns the PAT-based auth, or null if no connection. */
export async function getOrgAzureDevOpsAuth(
  organizationId: string,
): Promise<AzureDevOpsAuth | null> {
  const row = await prisma.orgAzureDevOpsConnection.findUnique({
    where: { organizationId },
    select: { azureOrganization: true, azureServerUrl: true, patEnc: true },
  });
  if (!row?.patEnc) return null;
  try {
    return {
      organization: row.azureOrganization,
      pat: decryptSecret(row.patEnc),
      ...(row.azureServerUrl ? { serverUrl: row.azureServerUrl } : {}),
    };
  } catch {
    return null;
  }
}

export async function saveOrgAzureDevOpsConnection(params: {
  organizationId: string;
  azureOrganization: string;
  pat: string;
  azureUser?: string | null;
  azureServerUrl?: string | null;
}): Promise<void> {
  const patEnc = encryptSecret(params.pat);
  const azureServerUrl = params.azureServerUrl?.trim() || null;
  await prisma.orgAzureDevOpsConnection.upsert({
    where: { organizationId: params.organizationId },
    create: {
      organizationId: params.organizationId,
      azureOrganization: params.azureOrganization,
      azureServerUrl,
      azureUser: params.azureUser ?? null,
      patEnc,
    },
    update: {
      azureOrganization: params.azureOrganization,
      azureServerUrl,
      azureUser: params.azureUser ?? null,
      patEnc,
    },
  });
}

export async function deleteOrgAzureDevOpsConnection(
  organizationId: string,
): Promise<void> {
  await prisma.orgAzureDevOpsConnection.deleteMany({
    where: { organizationId },
  });
}

export async function verifyAzureDevOpsAuth(
  auth: AzureDevOpsAuth,
): Promise<boolean> {
  const res = await azureGet<{ authenticatedUser?: unknown }>(
    auth,
    "/_apis/connectionData",
  );
  if (res.ok) return true;
  // Azure DevOps Server may reject api-version on connectionData (400); retry
  // without it before treating the credentials as invalid.
  if (res.status === 400) {
    const retry = await azureGet<{ authenticatedUser?: unknown }>(
      auth,
      "/_apis/connectionData",
      "",
    );
    return retry.ok;
  }
  return false;
}

export async function getOrgAzureDevOpsAuthOrThrow(
  organizationId: string,
): Promise<AzureDevOpsAuth> {
  const auth = await getOrgAzureDevOpsAuth(organizationId);
  if (!auth) {
    throw new AzureDevOpsCredentialsInvalidError(
      "Azure DevOps is not connected for this organization",
    );
  }
  const ok = await verifyAzureDevOpsAuth(auth);
  if (!ok) {
    await deleteOrgAzureDevOpsConnection(organizationId);
    throw new AzureDevOpsCredentialsInvalidError();
  }
  return auth;
}
