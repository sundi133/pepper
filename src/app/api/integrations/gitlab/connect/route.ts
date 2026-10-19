import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import {
  getGitLabConnectionStatus,
  saveOrgGitLabConnection,
  deleteOrgGitLabConnection,
  verifyGitLabToken,
  setGitLabCommitStatuses,
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
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const body = (await req.json()) as { accessToken?: string; hostUrl?: string; commitStatuses?: unknown };
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

  await saveOrgGitLabConnection({
    organizationId: orgId,
    accessToken,
    hostUrl,
    ...(typeof body.commitStatuses === "boolean" ? { commitStatuses: body.commitStatuses } : {}),
  });
  const status = await getGitLabConnectionStatus(orgId);

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "integration.created",
    resource: "integration",
    details: { username: user.username, hostUrl },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json({
    ...status,
    connected: true,
    username: user.username,
    hostUrl,
  });
}

/** Switch merge-request commit statuses on or off without reconnecting. */
export async function PATCH(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const body = (await req.json().catch(() => ({}))) as { commitStatuses?: unknown };
  if (typeof body.commitStatuses !== "boolean") {
    return NextResponse.json({ error: "commitStatuses (true or false) is required" }, { status: 400 });
  }
  if (!(await setGitLabCommitStatuses(orgId, body.commitStatuses))) {
    return NextResponse.json({ error: "GitLab is not connected" }, { status: 404 });
  }

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "integration.updated",
    resource: "integration",
    details: { provider: "gitlab", commitStatuses: body.commitStatuses },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json(await getGitLabConnectionStatus(orgId));
}

export async function DELETE(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

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
