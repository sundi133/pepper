/** GitHub OAuth for org repository connection (separate callback from NextAuth login). */

/** Scopes: profile + repo read (GitHub requires `repo` for private repository metadata/contents). */
export const GITHUB_REPO_OAUTH_SCOPES = ["read:user", "repo"] as const;

export function githubOAuthClientId(): string | null {
  return (
    process.env.GITHUB_OAUTH_CLIENT_ID?.trim() ||
    process.env.GITHUB_ID?.trim() ||
    null
  );
}

export function githubOAuthClientSecret(): string | null {
  return (
    process.env.GITHUB_OAUTH_CLIENT_SECRET?.trim() ||
    process.env.GITHUB_SECRET?.trim() ||
    null
  );
}

export function githubOAuthCallbackUrl(): string {
  const base = process.env.NEXTAUTH_URL?.replace(/\/$/, "") || "http://localhost:3000";
  return `${base}/api/integrations/github/callback`;
}

export function isGithubRepoOAuthConfigured(): boolean {
  return Boolean(githubOAuthClientId() && githubOAuthClientSecret());
}
