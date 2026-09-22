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
 * Clone URL for an on-prem Azure DevOps Server repo:
 *   {serverUrl}/{collection}/{project}/_git/{repo}
 * `serverUrl` is the host (+ optional virtual dir) up to the collection.
 */
export function azureDevOpsServerCloneUrl(
  serverUrl: string,
  collection: string,
  project: string,
  repo: string,
): string {
  const base = serverUrl.trim().replace(/\/+$/, "");
  return `${base}/${encodeURIComponent(collection)}/${encodeURIComponent(project)}/_git/${encodeURIComponent(repo)}`;
}

/**
 * Parse a repository reference in any of the forms Pepper accepts:
 *   - `project/repo` (org taken from the connected account)
 *   - `org/project/repo`
 *   - `https://dev.azure.com/{org}/{project}/_git/{repo}`
 *   - legacy `https://{org}.visualstudio.com/[{collection}/]{project}/_git/{repo}`
 *
 * URL host matching is exact (no substring test) so a look-alike host such as
 * `dev.azure.com.attacker.example` is rejected.
 *
 * When `serverBaseUrl` is set (on-prem Azure DevOps Server), a URL whose origin
 * matches it is parsed generically off the `_git` segment, with the collection
 * taken from `defaultOrganization` (the connected collection) — this is robust
 * regardless of how many virtual-directory segments precede the collection.
 */
export function parseAzureDevOpsRepoInput(
  input: string,
  defaultOrganization?: string,
  serverBaseUrl?: string,
): ParsedAzureDevOpsRepo | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  const dec = (s: string): string => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  };

  try {
    if (/^https?:\/\//i.test(trimmed)) {
      const u = new URL(trimmed);
      const host = u.hostname.toLowerCase();
      const parts = u.pathname
        .replace(/^\/+|\/+$/g, "")
        .split("/")
        .filter(Boolean);
      const gitIdx = parts.indexOf("_git");
      const repoSeg =
        gitIdx >= 0 ? parts[gitIdx + 1]?.replace(/\.git$/i, "") : undefined;

      // On-prem Azure DevOps Server: match the configured server origin and
      // extract project + repo around `_git`; collection comes from the
      // connection.
      if (serverBaseUrl && defaultOrganization) {
        try {
          const serverOrigin = new URL(serverBaseUrl).origin;
          if (u.origin === serverOrigin && gitIdx >= 1 && repoSeg) {
            return {
              organization: defaultOrganization,
              project: dec(parts[gitIdx - 1]),
              repo: dec(repoSeg),
            };
          }
        } catch {
          /* fall through to hosted-service parsing */
        }
      }

      // Modern: dev.azure.com/{org}/{project}/_git/{repo}
      if (host === "dev.azure.com") {
        if (gitIdx >= 2 && repoSeg) {
          return {
            organization: dec(parts[0]),
            project: dec(parts[gitIdx - 1]),
            repo: dec(repoSeg),
          };
        }
        return null;
      }

      // Legacy: {org}.visualstudio.com/[{collection}/]{project}/_git/{repo}
      if (host.endsWith(".visualstudio.com")) {
        const org = host.slice(0, -".visualstudio.com".length);
        if (org && gitIdx >= 1 && repoSeg) {
          return {
            organization: org,
            project: dec(parts[gitIdx - 1]),
            repo: dec(repoSeg),
          };
        }
        return null;
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
