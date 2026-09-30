import { NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import {
  deleteOrgGithubConnection,
  getGithubConnectionStatus,
  getOrgGithubAccessToken,
} from "@/lib/github-connection";
import { revokeGithubToken } from "@/lib/github-oauth";
import { isGithubRepoOAuthConfigured } from "@/lib/github-oauth-config";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const status = await getGithubConnectionStatus(orgId);
  return NextResponse.json({
    ...status,
    oauthConfigured: isGithubRepoOAuthConfigured(),
  });
}

export async function DELETE(req: Request) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const token = await getOrgGithubAccessToken(orgId);
  if (token) {
    await revokeGithubToken(token);
  }
  await deleteOrgGithubConnection(orgId);

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "integration.deleted",
    resource: "integration",
    details: { provider: "github" },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json({ success: true });
}
