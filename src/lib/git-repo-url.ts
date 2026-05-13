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
