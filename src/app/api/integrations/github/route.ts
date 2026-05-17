import { NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  deleteOrgGithubConnection,
  getGithubConnectionStatus,
  getOrgGithubAccessToken,
} from "@/lib/github-connection";
import { revokeGithubToken } from "@/lib/github-oauth";
import { isGithubRepoOAuthConfigured } from "@/lib/github-oauth-config";

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

export async function DELETE() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const token = await getOrgGithubAccessToken(orgId);
  if (token) {
    await revokeGithubToken(token);
  }
  await deleteOrgGithubConnection(orgId);

  return NextResponse.json({ success: true });
}
