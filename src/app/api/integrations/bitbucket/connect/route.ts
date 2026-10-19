import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import {
  saveOrgBitbucketConnection,
  saveOrgBitbucketTokenConnection,
  deleteOrgBitbucketConnection,
  getBitbucketConnectionStatus,
} from "@/lib/bitbucket-connection";
import { bitbucketGet } from "@/lib/bitbucket-api";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

/**
 * GET — return current connection status (whether the org has a Bitbucket
 * app password configured).
 */
export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const status = await getBitbucketConnectionStatus(orgId);
  return NextResponse.json(status);
}

/**
 * POST — save (or replace) the org's Bitbucket Cloud connection. Body:
 * `{ authType: "access_token" | "api_token", token, workspace }` (§3.2 of
 * docs/PR_REVIEW_PROVIDERS_SPEC.md), or the legacy
 * `{ username, appPassword, workspace? }`. Verifies the credentials by
 * calling `/user` before persisting; rejects on 401/403 so we never store
 * a broken token.
 */
export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  let body: { username?: unknown; appPassword?: unknown; workspace?: unknown; authType?: unknown; token?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  if (body.authType === "access_token" || body.authType === "api_token") {
    return connectWithToken(req, orgId, auth.session.user.id, body.authType, body.token, body.workspace);
  }

  const username =
    typeof body.username === "string" ? body.username.trim() : "";
  const appPassword =
    typeof body.appPassword === "string" ? body.appPassword.trim() : "";
  const workspace =
    typeof body.workspace === "string" && body.workspace.trim()
      ? body.workspace.trim()
      : null;

  if (!username || !appPassword) {
    return NextResponse.json(
      { error: "username and appPassword are required" },
      { status: 400 },
    );
  }

  if (!workspace) {
    return NextResponse.json(
      {
        error:
          "workspace is required (your Bitbucket workspace slug) to import repositories.",
      },
      { status: 400 },
    );
  }

  // Verify the credentials before persisting — Bitbucket returns 401 for
  // bad app passwords. /user requires the `account:read` scope on the app
  // password.
  const probe = await bitbucketGet<{ username?: string }>(
    { username, appPassword },
    "/user",
  );
  if (!probe.ok) {
    return NextResponse.json(
      {
        error:
          probe.status === 401 || probe.status === 403
            ? "Bitbucket rejected the credentials. Check the username and app password, and ensure the app password has the required scopes (account:read, repository:read, repository:write, pullrequest:write)."
            : `Bitbucket probe failed (${probe.status})`,
      },
      { status: 400 },
    );
  }

  await saveOrgBitbucketConnection({
    organizationId: orgId,
    username,
    appPassword,
    workspace,
  });

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "integration.created",
    resource: "integration",
    details: { provider: "bitbucket", username, workspace },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json({
    connected: true,
    username,
    workspace,
  });
}

const WORKSPACE_SLUG = /^[A-Za-z0-9_.-]{1,100}$/;

/** An access token or API token: verified against the workspace, then saved. */
async function connectWithToken(
  req: NextRequest,
  orgId: string,
  userId: string,
  authType: "access_token" | "api_token",
  rawToken: unknown,
  rawWorkspace: unknown,
) {
  const token = typeof rawToken === "string" ? rawToken.trim() : "";
  const workspace = typeof rawWorkspace === "string" ? rawWorkspace.trim() : "";
  if (!token) return NextResponse.json({ error: "token is required" }, { status: 400 });
  if (!WORKSPACE_SLUG.test(workspace)) {
    return NextResponse.json({ error: "workspace is required (your Bitbucket workspace slug)." }, { status: 400 });
  }
  const tokenAuth = { username: "", appPassword: "", token, authType };
  const probe = await bitbucketGet<{ values?: unknown[] }>(tokenAuth, `/repositories/${encodeURIComponent(workspace)}?pagelen=1`);
  if (!probe.ok) {
    const kind = authType === "api_token" ? "API token" : "access token";
    return NextResponse.json(
      {
        error:
          probe.status === 401 || probe.status === 403
            ? `Bitbucket rejected the ${kind} for workspace ${workspace}. Check the token, that it belongs to this workspace, and that it can read repositories and pull requests.`
            : probe.status === 404
              ? `Workspace ${workspace} was not found, or the token can't see it.`
              : `Bitbucket probe failed (${probe.status})`,
      },
      { status: 400 },
    );
  }
  // A display name when the token may read its user; access tokens' bots often can't.
  const me = await bitbucketGet<{ display_name?: string; username?: string }>(tokenAuth, "/user").catch(() => null);
  const username =
    (me?.ok && (me.data.display_name || me.data.username)) ||
    (authType === "access_token" ? `${workspace} access token` : "API token");

  await saveOrgBitbucketTokenConnection({ organizationId: orgId, authType, token, username, workspace });
  await writeAuditLog({
    organizationId: orgId,
    userId,
    action: "integration.created",
    resource: "integration",
    details: { provider: "bitbucket", authType, username, workspace },
    ipAddress: ipFromHeaders(req.headers),
  });
  return NextResponse.json({ connected: true, username, workspace, authType });
}

/** DELETE — disconnect Bitbucket for the org. */
export async function DELETE(req: Request) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;
  await deleteOrgBitbucketConnection(orgId);
  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "integration.deleted",
    resource: "integration",
    details: { provider: "bitbucket" },
    ipAddress: ipFromHeaders(req.headers),
  });
  return NextResponse.json({ connected: false });
}
