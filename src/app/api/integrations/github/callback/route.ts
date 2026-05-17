import { NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";
import { exchangeGithubCode } from "@/lib/github-oauth";
import { githubGet } from "@/lib/github-api";
import { saveOrgGithubConnection } from "@/lib/github-connection";
import {
  GITHUB_OAUTH_STATE_COOKIE,
  oauthStateCookieOptions,
  sanitizeOAuthReturnTo,
  verifyGithubOAuthState,
} from "@/lib/github-oauth-state";

function redirectWithError(message: string, returnTo?: string): NextResponse {
  const base = process.env.NEXTAUTH_URL?.replace(/\/$/, "") || "";
  const path = returnTo ?? "/repositories";
  const url = new URL(path, base);
  url.searchParams.set("github", "error");
  url.searchParams.set("message", message.slice(0, 200));
  return NextResponse.redirect(url);
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const error = searchParams.get("error");
  const errorDescription = searchParams.get("error_description");

  const cookieStore = await cookies();
  const cookieState = cookieStore.get(GITHUB_OAUTH_STATE_COOKIE)?.value;

  const state = searchParams.get("state");
  const payload = verifyGithubOAuthState(state || "", cookieState);
  const returnTo = sanitizeOAuthReturnTo(payload?.returnTo) ?? "/repositories";

  cookieStore.set(GITHUB_OAUTH_STATE_COOKIE, "", {
    ...oauthStateCookieOptions(),
    maxAge: 0,
  });

  if (error) {
    const msg =
      error === "access_denied"
        ? "GitHub access was denied. You can try again when ready."
        : errorDescription || error;
    return redirectWithError(msg, returnTo);
  }

  if (!payload) {
    return redirectWithError(
      "Invalid or expired authorization session. Please try connecting again.",
      returnTo,
    );
  }

  const code = searchParams.get("code");
  if (!code) {
    return redirectWithError("Missing authorization code from GitHub.", returnTo);
  }

  try {
    const tokenRes = await exchangeGithubCode(code);
    const userRes = await githubGet<{ id: number; login: string }>(
      tokenRes.access_token,
      "/user",
    );
    if (!userRes.ok) {
      return redirectWithError(
        "Could not verify GitHub account after authorization.",
        returnTo,
      );
    }

    await saveOrgGithubConnection({
      organizationId: payload.orgId,
      accessToken: tokenRes.access_token,
      scope: tokenRes.scope,
      githubUserId: String(userRes.data.id),
      githubLogin: userRes.data.login,
    });

    const base = process.env.NEXTAUTH_URL?.replace(/\/$/, "") || "";
    const url = new URL(returnTo, base);
    url.searchParams.set("github", "connected");
    if (returnTo === "/repositories" || returnTo.startsWith("/repositories?")) {
      url.searchParams.set("pick", "1");
    }
    return NextResponse.redirect(url);
  } catch (e) {
    const msg =
      e instanceof Error ? e.message : "Failed to complete GitHub authorization";
    return redirectWithError(msg, returnTo);
  }
}
