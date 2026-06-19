import crypto from "crypto";

const BITBUCKET_OAUTH_STATE_COOKIE = "bitbucket_oauth_state_v1";

const oauthStateCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  maxAge: 10 * 60, // 10 minutes
  path: "/",
});

interface StateData {
  orgId: string;
  userId: string;
  returnTo?: string;
  createdAt: number;
}

export function createBitbucketOAuthState(
  orgId: string,
  userId: string,
  options?: { returnTo?: string }
): { state: string; cookieValue: string } {
  const stateData: StateData = {
    orgId,
    userId,
    returnTo: options?.returnTo,
    createdAt: Date.now(),
  };

  const json = JSON.stringify(stateData);
  const encrypted = Buffer.from(json).toString("base64");

  return {
    state: encrypted,
    cookieValue: encrypted,
  };
}

export function decodeBitbucketOAuthState(state: string): StateData {
  try {
    const json = Buffer.from(state, "base64").toString("utf8");
    const data = JSON.parse(json) as StateData;

    // Verify state is not older than 10 minutes
    if (Date.now() - data.createdAt > 10 * 60 * 1000) {
      throw new Error("OAuth state expired");
    }

    return data;
  } catch (err) {
    throw new Error(
      `Invalid Bitbucket OAuth state: ${err instanceof Error ? err.message : "unknown error"}`
    );
  }
}

export function sanitizeOAuthReturnTo(returnTo: string | null): string | null {
  if (!returnTo) return null;
  if (!returnTo.startsWith("/")) return null;
  // Prevent open redirects
  if (returnTo.includes("://")) return null;
  return returnTo;
}

export { BITBUCKET_OAUTH_STATE_COOKIE, oauthStateCookieOptions };
