/** Bitbucket OAuth configuration */

export const BITBUCKET_REPO_OAUTH_SCOPES = ["repository", "pullrequest:read", "account"];

export function bitbucketOAuthClientId(): string {
  return (
    process.env.BITBUCKET_OAUTH_CLIENT_ID ||
    process.env.BITBUCKET_CLIENT_ID ||
    process.env.BITBUCKET_ID ||
    ""
  );
}

export function bitbucketOAuthClientSecret(): string {
  return (
    process.env.BITBUCKET_OAUTH_CLIENT_SECRET ||
    process.env.BITBUCKET_CLIENT_SECRET ||
    process.env.BITBUCKET_SECRET ||
    ""
  );
}

export function bitbucketOAuthCallbackUrl(): string {
  const baseUrl = process.env.NEXTAUTH_URL || process.env.VERCEL_URL || "http://localhost:3000";
  const url = baseUrl.startsWith("http") ? baseUrl : `https://${baseUrl}`;
  return `${url}/api/integrations/bitbucket/callback`;
}

export function isBitbucketOAuthConfigured(): boolean {
  return Boolean(bitbucketOAuthClientId() && bitbucketOAuthClientSecret());
}
