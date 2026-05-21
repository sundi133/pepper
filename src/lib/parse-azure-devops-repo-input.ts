/** `refs/heads/main` → `main`. */
export function parseAzureDevOpsRef(ref: string | null | undefined): string {
  const r = ref?.trim();
  if (!r) return "main";
  if (r.startsWith("refs/heads/")) {
    return r.slice("refs/heads/".length).trim() || "main";
  }
  return r;
}

export interface ParsedAzureDevOpsRepo {
  organization: string;
  project: string;
  repo: string;
}

export function azureDevOpsHttpsCloneUrl(
  organization: string,
  project: string,
  repo: string,
): string {
  return `https://dev.azure.com/${encodeURIComponent(organization)}/${encodeURIComponent(project)}/_git/${encodeURIComponent(repo)}`;
}

/**
 * Parse `project/repo`, `org/project/repo`, or
 * `https://dev.azure.com/org/project/_git/repo`.
 */
export function parseAzureDevOpsRepoInput(
  input: string,
  defaultOrganization?: string,
): ParsedAzureDevOpsRepo | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  try {
    if (/^https?:\/\//i.test(trimmed)) {
      const u = new URL(trimmed);
      if (!u.hostname.includes("dev.azure.com")) return null;
      const parts = u.pathname.replace(/^\/+|\/+$/g, "").split("/");
      // org / project / _git / repo
      const gitIdx = parts.indexOf("_git");
      if (gitIdx >= 2 && parts[gitIdx + 1]) {
        return {
          organization: parts[0],
          project: parts[gitIdx - 1],
          repo: parts[gitIdx + 1].replace(/\.git$/i, ""),
        };
      }
      return null;
    }
  } catch {
    return null;
  }

  const segments = trimmed.split("/").map((s) => s.trim()).filter(Boolean);
  if (segments.length === 2 && defaultOrganization) {
    return {
      organization: defaultOrganization,
      project: segments[0],
      repo: segments[1].replace(/\.git$/i, ""),
    };
  }
  if (segments.length === 3) {
    return {
      organization: segments[0],
      project: segments[1],
      repo: segments[2].replace(/\.git$/i, ""),
    };
  }

  return null;
}
