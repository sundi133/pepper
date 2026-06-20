import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  getGitLabConnectionStatus,
  saveOrgGitLabConnection,
  deleteOrgGitLabConnection,
  verifyGitLabToken,
  getOrgGitLabAuth,
} from "@/lib/gitlab-connection";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const status = await getGitLabConnectionStatus(orgId);
  return NextResponse.json(status);
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const body = (await req.json()) as { accessToken?: string; hostUrl?: string };
  const accessToken = body.accessToken?.trim();
  if (!accessToken) {
    return NextResponse.json({ error: "accessToken is required" }, { status: 400 });
  }

  const hostUrl = body.hostUrl?.trim() || "https://gitlab.com";

  // Verify the token before saving
  const user = await verifyGitLabToken({ hostUrl, accessToken });
  if (!user) {
    return NextResponse.json(
      { error: "Token verification failed. Check the token and host URL." },
      { status: 422 },
    );
  }

  await saveOrgGitLabConnection({ organizationId: orgId, accessToken, hostUrl });

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "integration.created",
    resource: "integration",
    details: { username: user.username, hostUrl },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json({
    connected: true,
    username: user.username,
    hostUrl,
  });
}

export async function DELETE(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  await deleteOrgGitLabConnection(orgId);

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "integration.deleted",
    resource: "integration",
    details: {},
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json({ disconnected: true });
}
