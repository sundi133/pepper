/**
 * Embed HTTP credentials for a one-off git clone. Use only in worker job payload —
 * do not persist URLs containing tokens on the Scan row.
 */
export function withGitCredentials(repoUrl: string, token: string): string {
  const t = token.trim();
  if (!t) return repoUrl;
  try {
    const u = new URL(repoUrl);
    if (u.protocol !== "http:" && u.protocol !== "https:") return repoUrl;
    u.username = encodeURIComponent(t);
    u.password = "";
    return u.toString();
  } catch {
    return repoUrl;
  }
}

/** Embed Bitbucket app-password auth for HTTPS clone (username + app password). */
export function withBitbucketCredentials(
  repoUrl: string,
  username: string,
  appPassword: string,
): string {
  const user = username.trim();
  const pass = appPassword.trim();
  if (!user || !pass) return repoUrl;
  try {
    const u = new URL(repoUrl);
    if (u.protocol !== "http:" && u.protocol !== "https:") return repoUrl;
    u.username = encodeURIComponent(user);
    u.password = encodeURIComponent(pass);
    return u.toString();
  } catch {
    return repoUrl;
  }
}

/** Embed Azure DevOps PAT for HTTPS clone (empty user, PAT as password). */
export function withAzureDevOpsCredentials(
  repoUrl: string,
  pat: string,
): string {
  const token = pat.trim();
  if (!token) return repoUrl;
  try {
    const u = new URL(repoUrl);
    if (u.protocol !== "http:" && u.protocol !== "https:") return repoUrl;
    u.username = "";
    u.password = encodeURIComponent(token);
    return u.toString();
  } catch {
    return repoUrl;
  }
}
