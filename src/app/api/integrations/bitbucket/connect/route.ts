import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  saveOrgBitbucketConnection,
  deleteOrgBitbucketConnection,
  getBitbucketConnectionStatus,
} from "@/lib/bitbucket-connection";
import { bitbucketGet } from "@/lib/bitbucket-api";

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

  let body: { username?: unknown; appPassword?: unknown; workspace?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
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

  return NextResponse.json({
    connected: true,
    username,
    workspace,
  });
}

/** DELETE — disconnect Bitbucket for the org. */
export async function DELETE() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  await deleteOrgBitbucketConnection(orgId);
  return NextResponse.json({ connected: false });
}
