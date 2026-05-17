import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { revokeApiKey } from "@/lib/api-key";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const { id } = await params;
  const res = await revokeApiKey(orgId, id);
  if (res.count === 0) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "apikey.revoked",
    resource: "apikey",
    resourceId: id,
    ipAddress: ipFromHeaders(req.headers),
  });
  return NextResponse.json({ ok: true });
}
