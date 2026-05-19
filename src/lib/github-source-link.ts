/**
 * Build GitHub / GitLab web URLs for "open this line in the repo" from a clone URL and ref.
 */

export interface ParsedGithubRepo {
  owner: string;
  repo: string;
}

export interface ParsedGitlabRepo {
  /** Full path_with_namespace, e.g. `group/subgroup/project`. */
  projectPath: string;
}

function stripUrlCredentials(repoUrl: string): string {
  try {
    const u = new URL(repoUrl);
    u.username = "";
    u.password = "";
    return u.toString();
  } catch {
    return repoUrl;
  }
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

function isAbsoluteWebUrl(filePath: string): boolean {
  return /^https?:\/\//i.test(filePath.trim());
}

function normalizeRepoFilePath(filePath: string): string {
  return filePath
    .trim()
    .replace(/\\/g, "/")
    .replace(/^\.\/+/, "")
    .replace(/^\/+/, "");
}

export function parseGithubRepo(
  repoUrl: string | null | undefined,
): ParsedGithubRepo | null {
  if (!repoUrl?.trim()) return null;
  const u = stripUrlCredentials(repoUrl.trim());

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

export function parseGitlabRepo(
  repoUrl: string | null | undefined,
): ParsedGitlabRepo | null {
  if (!repoUrl?.trim()) return null;
  const u = stripUrlCredentials(repoUrl.trim());

  try {
    const url = new URL(u.startsWith("http") ? u : `https://${u}`);
    const host = url.hostname.replace(/^www\./i, "").toLowerCase();
    const gitlabHost = process.env.GITLAB_URL
      ? new URL(process.env.GITLAB_URL).hostname.toLowerCase()
      : null;
    const isGitlab =
      host === "gitlab.com" ||
      host.endsWith(".gitlab.com") ||
      (gitlabHost != null && host === gitlabHost);
    if (!isGitlab) return null;
    const parts = url.pathname
      .split("/")
      .filter(Boolean)
      .map(stripGitSuffix);
    if (parts.length < 2) return null;
    return { projectPath: parts.join("/") };
  } catch {
    return null;
  }
}

/** Scan types where `sourceRef` holds the Git clone URL (never token-embedded in our DB). */
export function scanSourceRefIsGitCloneUrl(sourceType: string): boolean {
  return sourceType === "GIT_CLONE" || sourceType === "WEBHOOK";
}

/** Clone URL used for this scan (scan ref wins over stale project URL). */
export function resolveScanCloneRepoUrl(options: {
  projectRepoUrl: string | null | undefined;
  scanSourceType: string;
  scanSourceRef: string | null | undefined;
}): string | null {
  if (scanSourceRefIsGitCloneUrl(options.scanSourceType)) {
    const s = options.scanSourceRef?.trim();
    if (s) return stripUrlCredentials(s);
  }
  const p = options.projectRepoUrl?.trim();
  return p ? stripUrlCredentials(p) : null;
}

/**
 * Prefer the scan's clone URL, then the project URL, for GitHub-hosted repos.
 */
export function resolveGithubRepoUrlForOpenPr(options: {
  projectRepoUrl: string | null | undefined;
  scanSourceType: string;
  scanSourceRef: string | null | undefined;
}): string | null {
  const ordered: string[] = [];
  const scanClone = resolveScanCloneRepoUrl(options);
  if (scanClone) ordered.push(scanClone);
  const p = options.projectRepoUrl?.trim();
  if (p && p !== scanClone) ordered.push(stripUrlCredentials(p));
  for (const c of ordered) {
    if (parseGithubRepo(c)) return c;
  }
  return ordered.find((c) => parseGithubRepo(c)) ?? ordered[0] ?? null;
}

function resolveBlobRef(input: {
  commitSha?: string | null;
  branch?: string | null;
  defaultBranch?: string | null;
}): string {
  return (
    (input.commitSha && input.commitSha.length >= 7
      ? input.commitSha
      : input.branch?.trim()) ||
    input.defaultBranch?.trim() ||
    "main"
  );
}

/**
 * `https://github.com/{owner}/{repo}/blob/{ref}/{path}#L{line}`
 */
export function githubBlobLineUrl(input: {
  repoUrl: string | null | undefined;
  commitSha?: string | null;
  branch?: string | null;
  defaultBranch?: string | null;
  filePath: string | null | undefined;
  startLine?: number | null;
}): string | null {
  const parsed = parseGithubRepo(input.repoUrl);
  if (!parsed || !input.filePath?.trim()) return null;
  if (isAbsoluteWebUrl(input.filePath)) return null;

  const pathInRepo = normalizeRepoFilePath(input.filePath);
  if (!pathInRepo) return null;

  const ref = resolveBlobRef(input);
  const encodedPath = encodePathSegments(pathInRepo);
  const encodedRef = encodePathSegments(ref);
  const line =
    input.startLine != null && input.startLine > 0
      ? `#L${input.startLine}`
      : "";

  return `https://github.com/${parsed.owner}/${parsed.repo}/blob/${encodedRef}/${encodedPath}${line}`;
}

/**
 * `https://gitlab.com/{namespace}/{project}/-/blob/{ref}/{path}#L{line}`
 */
export function gitlabBlobLineUrl(input: {
  repoUrl: string | null | undefined;
  commitSha?: string | null;
  branch?: string | null;
  defaultBranch?: string | null;
  filePath: string | null | undefined;
  startLine?: number | null;
}): string | null {
  const parsed = parseGitlabRepo(input.repoUrl);
  if (!parsed || !input.filePath?.trim()) return null;
  if (isAbsoluteWebUrl(input.filePath)) return null;

  const pathInRepo = normalizeRepoFilePath(input.filePath);
  if (!pathInRepo) return null;

  const ref = resolveBlobRef(input);
  const encodedPath = encodePathSegments(pathInRepo);
  const encodedRef = encodeURIComponent(ref);
  const line =
    input.startLine != null && input.startLine > 0
      ? `#L${input.startLine}`
      : "";

  let origin = "https://gitlab.com";
  try {
    const raw = stripUrlCredentials(input.repoUrl!.trim());
    const url = new URL(raw.startsWith("http") ? raw : `https://${raw}`);
    origin = `${url.protocol}//${url.host}`;
  } catch {
    /* keep default */
  }

  return `${origin}/${encodePathSegments(parsed.projectPath)}/-/blob/${encodedRef}/${encodedPath}${line}`;
}

export type RepoFileLineLinkLabel =
  | "View on GitHub"
  | "View on GitLab"
  | "Open URL";

export function repoFileLineLink(input: {
  repoUrl: string | null | undefined;
  commitSha?: string | null;
  branch?: string | null;
  defaultBranch?: string | null;
  filePath: string | null | undefined;
  startLine?: number | null;
}): { url: string; label: RepoFileLineLinkLabel } | null {
  if (input.filePath?.trim() && isAbsoluteWebUrl(input.filePath)) {
    return { url: input.filePath.trim(), label: "Open URL" };
  }

  const gitlab = gitlabBlobLineUrl(input);
  if (gitlab) return { url: gitlab, label: "View on GitLab" };

  const github = githubBlobLineUrl(input);
  if (github) return { url: github, label: "View on GitHub" };

  return null;
}
