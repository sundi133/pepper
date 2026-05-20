import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  saveOrgAzureDevOpsConnection,
  deleteOrgAzureDevOpsConnection,
  getAzureDevOpsConnectionStatus,
} from "@/lib/azure-devops-connection";
import { azureGet } from "@/lib/azure-devops-api";

/** GET — current connection status for the calling user's default org. */
export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const status = await getAzureDevOpsConnectionStatus(orgId);
  return NextResponse.json(status);
}

/**
 * POST — save (or replace) the org's Azure DevOps connection. Body:
 * `{ azureOrganization, pat }`. Validates the PAT against
 * `/_apis/connectionData` before persisting; rejects on 401/403 so we
 * never store a broken token.
 */
export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  let body: { azureOrganization?: unknown; pat?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const azureOrganization =
    typeof body.azureOrganization === "string"
      ? body.azureOrganization.trim()
      : "";
  const pat = typeof body.pat === "string" ? body.pat.trim() : "";

  if (!azureOrganization || !pat) {
    return NextResponse.json(
      { error: "azureOrganization and pat are required" },
      { status: 400 },
    );
  }

  // Probe the connection: `/_apis/connectionData` returns the
  // authenticated user's identity info. Cheap, available with the
  // minimum scope, and fails fast on bad PATs.
  const probe = await azureGet<{
    authenticatedUser?: { providerDisplayName?: string };
  }>({ organization: azureOrganization, pat }, "/_apis/connectionData");

  if (!probe.ok) {
    return NextResponse.json(
      {
        error:
          probe.status === 401 || probe.status === 403
            ? "Azure DevOps rejected the credentials. Check the organization name and PAT, and ensure the PAT has 'Code (read & write)', 'Pull Request Threads (read & write)' and 'Project and Team (read)' scopes."
            : `Azure DevOps probe failed (${probe.status})`,
      },
      { status: 400 },
    );
  }

  const azureUser = probe.data.authenticatedUser?.providerDisplayName ?? null;

  await saveOrgAzureDevOpsConnection({
    organizationId: orgId,
    azureOrganization,
    pat,
    azureUser,
  });

  return NextResponse.json({
    connected: true,
    azureOrganization,
    azureUser,
  });
}

/** DELETE — remove the connection. */
export async function DELETE() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  await deleteOrgAzureDevOpsConnection(orgId);
  return NextResponse.json({ connected: false });
}
