import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { createApiKey, listApiKeys } from "@/lib/api-key";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const keys = await listApiKeys(orgId);
  return NextResponse.json({ keys });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const body = (await req.json()) as {
    name?: string;
    expiresAt?: string | null;
  };
  if (!body.name?.trim()) {
    return NextResponse.json({ error: "name is required" }, { status: 400 });
  }
  const created = await createApiKey({
    organizationId: orgId,
    createdBy: auth.session.user.id,
    name: body.name.trim(),
    expiresAt: body.expiresAt ? new Date(body.expiresAt) : null,
  });
  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "apikey.created",
    resource: "apikey",
    resourceId: created.id,
    details: { name: created.name, prefix: created.prefix },
    ipAddress: ipFromHeaders(req.headers),
  });
  return NextResponse.json(created, { status: 201 });
}
