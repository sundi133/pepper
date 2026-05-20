import { prisma } from "./prisma";
import { decryptSecret, encryptSecret } from "./token-encryption";
import type { AzureDevOpsAuth } from "./azure-devops-api";

export interface AzureDevOpsConnectionStatus {
  connected: boolean;
  azureOrganization: string | null;
  azureUser: string | null;
  connectedAt: string | null;
}

export async function getAzureDevOpsConnectionStatus(
  organizationId: string,
): Promise<AzureDevOpsConnectionStatus> {
  const row = await prisma.orgAzureDevOpsConnection.findUnique({
    where: { organizationId },
    select: { azureOrganization: true, azureUser: true, createdAt: true },
  });
  if (!row) {
    return {
      connected: false,
      azureOrganization: null,
      azureUser: null,
      connectedAt: null,
    };
  }
  return {
    connected: true,
    azureOrganization: row.azureOrganization,
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
    select: { azureOrganization: true, patEnc: true },
  });
  if (!row?.patEnc) return null;
  try {
    return {
      organization: row.azureOrganization,
      pat: decryptSecret(row.patEnc),
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
}): Promise<void> {
  const patEnc = encryptSecret(params.pat);
  await prisma.orgAzureDevOpsConnection.upsert({
    where: { organizationId: params.organizationId },
    create: {
      organizationId: params.organizationId,
      azureOrganization: params.azureOrganization,
      azureUser: params.azureUser ?? null,
      patEnc,
    },
    update: {
      azureOrganization: params.azureOrganization,
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
