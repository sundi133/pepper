import {
  GITHUB_REPO_OAUTH_SCOPES,
  githubOAuthCallbackUrl,
  githubOAuthClientId,
  githubOAuthClientSecret,
} from "@/lib/github-oauth-config";

const GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN = "https://github.com/login/oauth/access_token";

export type GithubTokenResponse = {
  access_token: string;
  token_type?: string;
  scope?: string;
  error?: string;
  error_description?: string;
};

export function buildGithubAuthorizeUrl(state: string): string {
  const clientId = githubOAuthClientId();
  if (!clientId) {
    throw new Error("GitHub OAuth is not configured (GITHUB_OAUTH_CLIENT_ID or GITHUB_ID)");
  }
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: githubOAuthCallbackUrl(),
    scope: GITHUB_REPO_OAUTH_SCOPES.join(" "),
    state,
    allow_signup: "true",
  });
  return `${GITHUB_AUTHORIZE}?${params.toString()}`;
}

export async function exchangeGithubCode(
  code: string,
): Promise<GithubTokenResponse> {
  const clientId = githubOAuthClientId();
  const clientSecret = githubOAuthClientSecret();
  if (!clientId || !clientSecret) {
    throw new Error("GitHub OAuth credentials are not configured");
  }

  const res = await fetch(GITHUB_TOKEN, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: githubOAuthCallbackUrl(),
    }),
  });

  const data = (await res.json()) as GithubTokenResponse;
  if (!res.ok || data.error) {
    throw new Error(
      data.error_description || data.error || "Failed to exchange GitHub authorization code",
    );
  }
  if (!data.access_token) {
    throw new Error("GitHub did not return an access token");
  }
  return data;
}

/** Revoke token via GitHub API (best-effort). */
export async function revokeGithubToken(accessToken: string): Promise<void> {
  const clientId = githubOAuthClientId();
  const clientSecret = githubOAuthClientSecret();
  if (!clientId || !clientSecret) return;

  const auth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
  await fetch(
    `https://api.github.com/applications/${clientId}/token`,
    {
      method: "DELETE",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ access_token: accessToken }),
    },
  ).catch(() => {
    /* ignore */
  });
}
