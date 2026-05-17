const FALLBACK = "New project";

/** Derive a display name like `owner/repo` from a Git remote URL. */
export function projectNameFromGitUrl(url: string): string {
  const raw = url.trim();
  if (!raw) return FALLBACK;

  const scp = raw.match(/^[^@]+@([^:]+):(.+)$/);
  if (scp) {
    const path = scp[2].replace(/\.git$/i, "");
    const parts = path.split("/").filter(Boolean);
    if (parts.length >= 2) {
      return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`.slice(
        0,
        100,
      );
    }
    if (parts.length === 1) return parts[0].slice(0, 100);
  }

  try {
    const normalized = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const u = new URL(normalized);
    let path = u.pathname.replace(/\/+$/, "").replace(/\.git$/i, "");
    const parts = path.split("/").filter(Boolean);
    if (parts.length >= 2) {
      return `${parts[parts.length - 2]}/${parts[parts.length - 1]}`.slice(
        0,
        100,
      );
    }
    if (parts.length === 1) return parts[0].slice(0, 100);
    const host = u.hostname.replace(/^www\./, "");
    return (host || FALLBACK).slice(0, 100);
  } catch {
    return FALLBACK;
  }
}

export function projectNameFromUploadFilename(fileName: string): string {
  const base = fileName
    .replace(/.*[/\\]/, "")
    .replace(/\.(zip|tar\.gz|tgz|tar)$/i, "")
    .trim();
  return (base || FALLBACK).slice(0, 100);
}

export function projectNameFromSvnUrl(url: string): string {
  try {
    const u = new URL(url.trim());
    const segs = u.pathname.split("/").filter(Boolean);
    const last = segs[segs.length - 1] || u.hostname || FALLBACK;
    return last.slice(0, 100);
  } catch {
    return FALLBACK;
  }
}
