import { NextResponse } from "next/server";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";

export async function DELETE(req: Request) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  const roleAuth = await requireRole(orgId, "ADMIN");
  if ("error" in roleAuth) return roleAuth.error;

  try {
    await prisma.orgSettings.update({
      where: { organizationId: orgId },
      data: { llmApiKey: null },
    });
    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "settings.llm.updated",
      resource: "settings",
      resourceId: orgId,
      details: { apiKeyRemoved: true },
      ipAddress: ipFromHeaders(req.headers),
    });
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json(
      { error: "Failed to delete API key" },
      { status: 500 },
    );
  }
}