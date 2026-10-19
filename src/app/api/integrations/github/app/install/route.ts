import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { GITHUB_APP_STATE_COOKIE, githubAppConfig, githubAppInstallUrl } from "@/lib/github-app";
import { createGithubOAuthState, oauthStateCookieOptions } from "@/lib/github-oauth-state";

/**
 * Start installing the GitHub App for this organization (docs/GITHUB_APP_SPEC.md §5):
 * a signed, expiring state bound to the user and organization, then GitHub's
 * install page. Admins and Security only.
 */
export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const cfg = githubAppConfig();
  if (!cfg) {
    return NextResponse.json(
      { error: "The GitHub App is not configured on this Pepper server (GITHUB_APP_* settings)." },
      { status: 503 },
    );
  }

  const { state, cookieValue } = createGithubOAuthState(orgId, auth.session.user.id, { returnTo: "/settings/integrations" });
  const cookieStore = await cookies();
  cookieStore.set(GITHUB_APP_STATE_COOKIE, cookieValue, oauthStateCookieOptions());
  return NextResponse.redirect(githubAppInstallUrl(cfg, state));
}
