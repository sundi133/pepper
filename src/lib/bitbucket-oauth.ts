import {
  BITBUCKET_REPO_OAUTH_SCOPES,
  bitbucketOAuthCallbackUrl,
  bitbucketOAuthClientId,
  bitbucketOAuthClientSecret,
} from "@/lib/bitbucket-oauth-config";

const BITBUCKET_AUTHORIZE = "https://bitbucket.org/site/oauth2/authorize";
const BITBUCKET_TOKEN = "https://bitbucket.org/site/oauth2/access_token";

export type BitbucketTokenResponse = {
  access_token: string;
  token_type?: string;
  scope?: string;
  expires_in?: number;
  refresh_token?: string;
  error?: string;
  error_description?: string;
};

export function buildBitbucketAuthorizeUrl(state: string): string {
  const clientId = bitbucketOAuthClientId();
  if (!clientId) {
    throw new Error(
      "Bitbucket OAuth is not configured (BITBUCKET_OAUTH_CLIENT_ID or BITBUCKET_ID)"
    );
  }
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: bitbucketOAuthCallbackUrl(),
    response_type: "code",
    state,
    scopes: BITBUCKET_REPO_OAUTH_SCOPES.join(" "),
  });
  return `${BITBUCKET_AUTHORIZE}?${params.toString()}`;
}

export async function exchangeBitbucketCode(
  code: string
): Promise<BitbucketTokenResponse> {
  const clientId = bitbucketOAuthClientId();
  const clientSecret = bitbucketOAuthClientSecret();
  if (!clientId || !clientSecret) {
    throw new Error("Bitbucket OAuth credentials are not configured");
  }

  const auth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
  const res = await fetch(BITBUCKET_TOKEN, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      code,
      grant_type: "authorization_code",
      redirect_uri: bitbucketOAuthCallbackUrl(),
    }).toString(),
  });

  const data = (await res.json()) as BitbucketTokenResponse;
  if (!res.ok || data.error) {
    throw new Error(
      data.error_description || data.error || "Failed to exchange Bitbucket authorization code"
    );
  }
  if (!data.access_token) {
    throw new Error("Bitbucket did not return an access token");
  }
  return data;
}

/** Revoke token via Bitbucket API (best-effort). */
export async function revokeBitbucketToken(accessToken: string): Promise<void> {
  try {
    await fetch("https://bitbucket.org/site/oauth2/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        token: accessToken,
      }).toString(),
    });
  } catch {
    /* ignore */
  }
}
