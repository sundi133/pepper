import { prisma } from "./prisma";
import { decryptSecret, encryptSecret } from "./token-encryption";
import { azureGet } from "./azure-devops-api";
import type { AzureDevOpsAuth } from "./azure-devops-api";
import { getEntraAccessToken } from "./azure-devops-entra";
import { logger } from "./logger";

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
  /** "pat" | "service_principal" */
  authType: string | null;
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
      authType: true,
    },
  });
  if (!row) {
    return {
      connected: false,
      azureOrganization: null,
      azureServerUrl: null,
      azureUser: null,
      connectedAt: null,
      authType: null,
    };
  }
  return {
    connected: true,
    azureOrganization: row.azureOrganization,
    azureServerUrl: row.azureServerUrl ?? null,
    azureUser: row.azureUser ?? null,
    connectedAt: row.createdAt.toISOString(),
    authType: row.authType,
  };
}

/**
 * The connection's auth, or null if there is none: the PAT, or for a service
 * principal a fresh Entra ID token in `bearer` (docs/PR_REVIEW_PROVIDERS_SPEC.md §1.2).
 */
export async function getOrgAzureDevOpsAuth(
  organizationId: string,
): Promise<AzureDevOpsAuth | null> {
  const row = await prisma.orgAzureDevOpsConnection.findUnique({
    where: { organizationId },
    select: { azureOrganization: true, azureServerUrl: true, patEnc: true, authType: true, tenantId: true, clientId: true, clientSecretEnc: true },
  });
  if (row?.authType === "service_principal") {
    if (!row.tenantId || !row.clientId || !row.clientSecretEnc) return null;
    try {
      const bearer = await getEntraAccessToken({ tenantId: row.tenantId, clientId: row.clientId, clientSecret: decryptSecret(row.clientSecretEnc) });
      return { organization: row.azureOrganization, pat: "", bearer };
    } catch (err) {
      logger.warn({ err: err instanceof Error ? err.message : String(err) }, "Azure DevOps service principal token failed");
      return null;
    }
  }
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
      // Switching back to a PAT clears any service principal.
      authType: "pat",
      tenantId: null,
      clientId: null,
      clientSecretEnc: null,
    },
  });
}

/** Save a service principal connection (Azure DevOps Services only). */
export async function saveOrgAzureDevOpsServicePrincipal(params: {
  organizationId: string;
  azureOrganization: string;
  tenantId: string;
  clientId: string;
  clientSecret: string;
  azureUser?: string | null;
}): Promise<void> {
  const data = {
    azureOrganization: params.azureOrganization,
    azureServerUrl: null,
    azureUser: params.azureUser ?? null,
    authType: "service_principal",
    tenantId: params.tenantId.trim(),
    clientId: params.clientId.trim(),
    clientSecretEnc: encryptSecret(params.clientSecret),
    patEnc: null,
  };
  await prisma.orgAzureDevOpsConnection.upsert({
    where: { organizationId: params.organizationId },
    create: { organizationId: params.organizationId, ...data },
    update: data,
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
    // A revoked PAT is removed, as before. A service principal is kept: the
    // usual cause is a missing Azure DevOps permission, which an admin fixes.
    if (!auth.bearer) await deleteOrgAzureDevOpsConnection(organizationId);
    throw new AzureDevOpsCredentialsInvalidError(
      auth.bearer
        ? "Azure DevOps refused the service principal. Add it to the Azure DevOps organization (Organization settings → Users) with access to the projects to scan."
        : undefined,
    );
  }
  return auth;
}
