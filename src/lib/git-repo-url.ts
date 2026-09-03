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

/**
 * Strip a credential-bearing clone URL out of a thrown error's message
 * (and stack) before it can propagate further.
 *
 * `execFileSync`'s thrown error embeds the full argv — including the
 * credentialed clone URL built by `withGitCredentials`/
 * `withBitbucketCredentials`/`withAzureDevOpsCredentials` — in its
 * `.message`. That message is persisted as `Scan.errorMessage`, rendered on
 * the scan detail page, and posted (truncated) as a PR comment, so a raw
 * clone failure would otherwise leak the org's live OAuth token/app
 * password/PAT to anyone who can see that scan or PR. Call this at every
 * git-clone catch site, replacing the credentialed URL with the safe
 * display URL (`repoUrlDisplay`/`repoLog`) before rethrowing.
 */
export function sanitizeGitCloneError(
  err: unknown,
  sensitiveUrl: string,
  safeUrl: string,
): Error {
  const original = err instanceof Error ? err : new Error(String(err));
  if (!sensitiveUrl || sensitiveUrl === safeUrl) return original;
  const sanitized = new Error(
    original.message.split(sensitiveUrl).join(safeUrl),
  );
  sanitized.name = original.name;
  if (original.stack) {
    sanitized.stack = original.stack.split(sensitiveUrl).join(safeUrl);
  }
  return sanitized;
}
