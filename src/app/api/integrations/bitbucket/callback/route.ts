import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { exchangeBitbucketCode } from "@/lib/bitbucket-oauth";
import {
  decodeBitbucketOAuthState,
  BITBUCKET_OAUTH_STATE_COOKIE,
  sanitizeOAuthReturnTo,
} from "@/lib/bitbucket-oauth-state";
import { prisma } from "@/lib/prisma";
import { encryptSecret } from "@/lib/token-encryption";
import { cookies } from "next/headers";

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { searchParams } = new URL(req.url);
  const code = searchParams.get("code");
  const state = searchParams.get("state");
  const error = searchParams.get("error");
  const errorDescription = searchParams.get("error_description");

  // Handle OAuth errors from Bitbucket
  if (error) {
    return NextResponse.redirect(
      `/settings/integrations?error=bitbucket_${error}&description=${encodeURIComponent(
        errorDescription || error
      )}`
    );
  }

  if (!code || !state) {
    return NextResponse.json(
      { error: "Missing code or state parameter" },
      { status: 400 }
    );
  }

  // Verify state
  let stateData;
  try {
    stateData = decodeBitbucketOAuthState(state);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Invalid state" },
      { status: 400 }
    );
  }

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId || orgId !== stateData.orgId) {
    return NextResponse.json(
      { error: "Organization mismatch" },
      { status: 403 }
    );
  }

  // Exchange code for token
  let tokenResponse;
  try {
    tokenResponse = await exchangeBitbucketCode(code);
  } catch (err) {
    return NextResponse.redirect(
      `/settings/integrations?error=bitbucket_token_exchange&description=${encodeURIComponent(
        err instanceof Error ? err.message : "Failed to exchange token"
      )}`
    );
  }

  // Get user info to get username
  try {
    const userRes = await fetch("https://api.bitbucket.org/2.0/user", {
      headers: {
        Authorization: `Bearer ${tokenResponse.access_token}`,
        Accept: "application/json",
      },
    });

    if (!userRes.ok) {
      throw new Error("Failed to fetch Bitbucket user info");
    }

    const userData = (await userRes.json()) as { username?: string };
    const username = userData.username;

    if (!username) {
      throw new Error("Could not get Bitbucket username");
    }

    // Store the connection with OAuth token
    const encryptedToken = encryptSecret(tokenResponse.access_token);

    await prisma.orgBitbucketConnection.upsert({
      where: { organizationId: orgId },
      update: {
        username,
        appPasswordEnc: encryptedToken,
        workspace: null, // Will be fetched from API
        updatedAt: new Date(),
      },
      create: {
        organizationId: orgId,
        username,
        appPasswordEnc: encryptedToken,
        workspace: null,
      },
    });

    // Clear OAuth state cookie
    const cookieStore = await cookies();
    cookieStore.delete(BITBUCKET_OAUTH_STATE_COOKIE);

    // Redirect to return URL or default
    const returnTo = sanitizeOAuthReturnTo(stateData.returnTo ?? null) ?? "/settings/integrations";
    return NextResponse.redirect(new URL(returnTo, req.url));
  } catch (err) {
    console.error("Bitbucket OAuth callback error:", err);
    return NextResponse.redirect(
      `/settings/integrations?error=bitbucket_setup&description=${encodeURIComponent(
        err instanceof Error ? err.message : "Failed to setup Bitbucket"
      )}`
    );
  }
}
