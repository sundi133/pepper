import { NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import {
  getOrgAzureDevOpsAuthOrThrow,
  getAzureDevOpsConnectionStatus,
  AzureDevOpsCredentialsInvalidError,
} from "@/lib/azure-devops-connection";
import { listAzureDevOpsRepositoriesInOrganization } from "@/lib/azure-devops-repos";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  try {
    const status = await getAzureDevOpsConnectionStatus(orgId);
    if (!status.connected || !status.azureOrganization) {
      return NextResponse.json(
        {
          error:
            "Connect Azure DevOps under Settings → Integrations to browse repositories.",
          code: "AZURE_DEVOPS_NOT_CONNECTED",
        },
        { status: 400 },
      );
    }

    const adoAuth = await getOrgAzureDevOpsAuthOrThrow(orgId);

    const existing = await prisma.project.findMany({
      where: {
        organizationId: orgId,
        azureRepoId: { not: null },
      },
      select: { azureRepoId: true },
    });
    const connectedIds = new Set(
      existing
        .map((p) => p.azureRepoId)
        .filter((id): id is string => id != null),
    );

    const repositories = await listAzureDevOpsRepositoriesInOrganization(
      adoAuth,
      connectedIds,
    );

    return NextResponse.json({
      repositories,
      azureOrganization: status.azureOrganization,
    });
  } catch (e) {
    if (e instanceof AzureDevOpsCredentialsInvalidError) {
      return NextResponse.json(
        {
          error:
            "Azure DevOps connection expired or was revoked. Connect again under Settings → Integrations.",
          code: "AZURE_DEVOPS_CREDENTIALS_INVALID",
        },
        { status: 401 },
      );
    }
    const msg = e instanceof Error ? e.message : "Failed to list repositories";
    return NextResponse.json({ error: msg }, { status: 502 });
  }
}
