import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { buildGithubAuthorizeUrl } from "@/lib/github-oauth";
import {
  createGithubOAuthState,
  GITHUB_OAUTH_STATE_COOKIE,
  oauthStateCookieOptions,
  sanitizeOAuthReturnTo,
} from "@/lib/github-oauth-state";
import { isGithubRepoOAuthConfigured } from "@/lib/github-oauth-config";
import { cookies } from "next/headers";

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  if (!isGithubRepoOAuthConfigured()) {
    return NextResponse.json(
      {
        error:
          "GitHub OAuth is not configured. Set GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET (or GITHUB_ID / GITHUB_SECRET) and register callback URL in your GitHub OAuth app.",
      },
      { status: 503 },
    );
  }

  const returnTo =
    sanitizeOAuthReturnTo(req.nextUrl.searchParams.get("returnTo")) ??
    "/scans/new";

  const { state, cookieValue } = createGithubOAuthState(
    orgId,
    auth.session.user.id,
    { returnTo },
  );

  const cookieStore = await cookies();
  cookieStore.set(GITHUB_OAUTH_STATE_COOKIE, cookieValue, oauthStateCookieOptions());

  const url = buildGithubAuthorizeUrl(state);
  return NextResponse.redirect(url);
}
