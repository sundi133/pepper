/** Strip Bitbucket UUID braces: `{abc}` → `abc`. */
export function normalizeBitbucketUuid(uuid: string): string {
  return uuid.replace(/^\{|\}$/g, "").trim();
}

export interface ParsedBitbucketRepo {
  workspace: string;
  slug: string;
}

/** Parse `workspace/repo-slug` or `https://bitbucket.org/workspace/repo-slug`. */
export function parseBitbucketRepoInput(
  input: string,
): ParsedBitbucketRepo | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  try {
    if (/^https?:\/\//i.test(trimmed)) {
      const u = new URL(trimmed);
      if (!u.hostname.includes("bitbucket.org")) return null;
      const parts = u.pathname.replace(/^\/+|\/+$/g, "").split("/");
      if (parts.length >= 2 && parts[0] && parts[1]) {
        const slug = parts[1].replace(/\.git$/i, "");
        return { workspace: parts[0], slug };
      }
      return null;
    }
  } catch {
    return null;
  }

  const slash = trimmed.match(/^([^/]+)\/([^/]+)$/);
  if (slash) {
    return {
      workspace: slash[1].trim(),
      slug: slash[2].replace(/\.git$/i, "").trim(),
    };
  }

  return null;
}

export function bitbucketHttpsCloneUrl(workspace: string, slug: string): string {
  return `https://bitbucket.org/${workspace}/${slug}.git`;
}
