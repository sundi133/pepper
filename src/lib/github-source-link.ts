/**
 * Build GitHub web URLs for "open this line in the repo" from a clone URL and ref.
 */

export interface ParsedGithubRepo {
  owner: string;
  repo: string;
}

export function parseGithubRepo(
  repoUrl: string | null | undefined,
): ParsedGithubRepo | null {
  if (!repoUrl?.trim()) return null;
  const u = repoUrl.trim();

  /** SCP form: git@github.com:owner/repo(.git) */
  const scp = u.match(/^git@github\.com:([^/]+)\/([^/.]+)(?:\.git)?$/i);
  if (scp) {
    return { owner: scp[1], repo: stripGitSuffix(scp[2]) };
  }

  if (
    /^https?:\/\//i.test(u) ||
    /^git:\/\//i.test(u) ||
    /^ssh:\/\//i.test(u)
  ) {
    try {
      const url = new URL(u);
      const host = url.hostname.replace(/^www\./i, "").toLowerCase();
      if (host !== "github.com") return null;
      const parts = url.pathname.split("/").filter(Boolean);
      if (parts.length < 2) return null;
      return { owner: parts[0], repo: stripGitSuffix(parts[1]) };
    } catch {
      return null;
    }
  }

  return null;
}

/** Scan types where `sourceRef` holds the Git clone URL (never token-embedded in our DB). */
export function scanSourceRefIsGitCloneUrl(sourceType: string): boolean {
  return sourceType === "GIT_CLONE" || sourceType === "WEBHOOK";
}

/**
 * Prefer the project's stored URL; if it is missing or not GitHub, fall back to the scan's
 * Git clone URL so "Open fix PR" works for projects created without `repoUrl` populated.
 */
export function resolveGithubRepoUrlForOpenPr(options: {
  projectRepoUrl: string | null | undefined;
  scanSourceType: string;
  scanSourceRef: string | null | undefined;
}): string | null {
  const ordered: string[] = [];
  const p = options.projectRepoUrl?.trim();
  if (p) ordered.push(p);
  if (scanSourceRefIsGitCloneUrl(options.scanSourceType)) {
    const s = options.scanSourceRef?.trim();
    if (s && s !== p) ordered.push(s);
  }
  for (const c of ordered) {
    if (parseGithubRepo(c)) return c;
  }
  return ordered[0] ?? null;
}

function stripGitSuffix(name: string): string {
  return name.replace(/\.git$/i, "");
}

/** Encode each path segment for URL (preserves slashes between segments). */
function encodePathSegments(p: string): string {
  return p
    .split("/")
    .filter(Boolean)
    .map((s) => encodeURIComponent(s))
    .join("/");
}

/**
 * `https://github.com/{owner}/{repo}/blob/{ref}/{path}#L{line}`
 * Returns null if `repoUrl` is not a github.com clone URL or `filePath` is empty.
 */
export function githubBlobLineUrl(input: {
  repoUrl: string | null | undefined;
  /** Prefer full commit SHA when present (stable line pointer). */
  commitSha?: string | null;
  branch?: string | null;
  defaultBranch?: string | null;
  filePath: string | null | undefined;
  startLine?: number | null;
}): string | null {
  const parsed = parseGithubRepo(input.repoUrl);
  if (!parsed || !input.filePath?.trim()) return null;

  const ref =
    (input.commitSha && input.commitSha.length >= 7
      ? input.commitSha
      : input.branch?.trim()) ||
    input.defaultBranch?.trim() ||
    "main";

  const pathInRepo = input.filePath.replace(/^[/\\]+/, "").replace(/\\/g, "/");
  const encodedPath = encodePathSegments(pathInRepo);
  const encodedRef = encodePathSegments(ref);

  const line =
    input.startLine != null && input.startLine > 0
      ? `#L${input.startLine}`
      : "";

  return `https://github.com/${parsed.owner}/${parsed.repo}/blob/${encodedRef}/${encodedPath}${line}`;
}
