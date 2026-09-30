import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import {
  IntegrationNotFoundError,
  findSameTargetIntegration,
  listIntegrations,
  upsertIntegration,
  type IntegrationConfigData,
} from "@/lib/integrations";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import { boardsConfigError } from "@/lib/integrations/azure-boards";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const integrations = await listIntegrations(orgId);
  return NextResponse.json({ integrations });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const body = (await req.json()) as IntegrationConfigData & {
    id?: string;
    name?: string;
    enabled?: boolean;
  };

  if (!body.kind || !body.config) {
    return NextResponse.json(
      { error: "kind and config are required" },
      { status: 400 },
    );
  }

  if (body.kind === "AZURE_BOARDS") {
    const error = boardsConfigError(body.config);
    if (error) return NextResponse.json({ error }, { status: 400 });
  }

  // Saving a board / Jira project that already has an integration updates it.
  let updatedExisting = false;
  if (!body.id) {
    const existingId = await findSameTargetIntegration(orgId, body);
    if (existingId) {
      body.id = existingId;
      updatedExisting = true;
    }
  }

  let row;
  try {
    row = await upsertIntegration(orgId, body);
  } catch (e) {
    if (e instanceof IntegrationNotFoundError) {
      return NextResponse.json({ error: "Not found" }, { status: 404 });
    }
    throw e;
  }

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: body.id ? "integration.updated" : "integration.created",
    resource: "integration",
    resourceId: row.id,
    details: { kind: row.kind, name: row.name, enabled: row.enabled },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json({
    id: row.id,
    kind: row.kind,
    name: row.name,
    enabled: row.enabled,
    updatedExisting,
  });
}
