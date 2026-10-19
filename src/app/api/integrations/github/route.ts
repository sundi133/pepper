import { NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { NextRequest } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import {
  deleteOrgGithubConnection,
  getGithubConnectionStatus,
} from "@/lib/github-connection";
import { getOrgGithubOAuthToken, isPersonalGithubAllowed } from "@/lib/github-token-resolve";
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
    allowPersonalGithub: await isPersonalGithubAllowed(orgId),
  });
}

const policySchema = z.object({ allowPersonalGithub: z.boolean() });

/**
 * Organization policy: whether personal GitHub connections may be used. Off
 * means GitHub App only (docs/PR_REVIEW_BOT_SPEC.md §6). Admin or Security.
 */
export async function PATCH(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const parsed = policySchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "allowPersonalGithub (boolean) is required" }, { status: 400 });
  await prisma.orgSettings.upsert({
    where: { organizationId: orgId },
    create: { organizationId: orgId, allowPersonalGithub: parsed.data.allowPersonalGithub },
    update: { allowPersonalGithub: parsed.data.allowPersonalGithub },
  });
  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "settings.updated",
    resource: "settings",
    details: { allowPersonalGithub: parsed.data.allowPersonalGithub },
    ipAddress: ipFromHeaders(req.headers),
  });
  return NextResponse.json({ allowPersonalGithub: parsed.data.allowPersonalGithub });
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

  // Only the personal connection is disconnected (never an App token).
  const token = await getOrgGithubOAuthToken(orgId);
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
