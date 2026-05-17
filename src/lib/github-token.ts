/**
 * Reject obvious garbage (e.g. pasted HTML / full UI) before storing or sending to GitHub.
 * GitHub classic PATs: ghp_<36+ alnum>. Fine-grained: github_pat_<...>
 */
export function isPlausibleGithubPersonalAccessToken(raw: string): boolean {
  const s = raw.trim();
  if (s.length < 30 || s.length > 2048) return false;
  if (/[\s\r\n\t<>"']/.test(s)) return false;
  return /^(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9]{20,}|ghu_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|ghr_[A-Za-z0-9]{20,})$/.test(
    s,
  );
}
