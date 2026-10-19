import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { forgetInstallationToken } from "@/lib/github-app";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

/**
 * Unlink a GitHub App installation from this organization. The App stays
 * installed on GitHub (uninstall it there); repositories it covered fall back
 * to the OAuth connection, if any.
 */
export async function DELETE(req: NextRequest, { params }: { params: Promise<{ installationId: string }> }) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const { installationId } = await params;
  if (!/^\d{1,19}$/.test(installationId)) return NextResponse.json({ error: "Invalid installation id" }, { status: 400 });
  const row = await prisma.orgGithubAppInstallation.findFirst({ where: { installationId: BigInt(installationId), organizationId: orgId } });
  if (!row) return NextResponse.json({ error: "Installation not found" }, { status: 404 });

  await prisma.orgGithubAppInstallation.delete({ where: { id: row.id } });
  forgetInstallationToken(row.installationId);
  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "github_app.removed",
    resource: "integration",
    details: { installationId, account: row.accountLogin },
    ipAddress: ipFromHeaders(req.headers),
  });
  return NextResponse.json({ ok: true });
}
