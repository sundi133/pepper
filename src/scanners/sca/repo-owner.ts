/**
 * Compare the source repositories of two packages to decide whether they are
 * the same project.
 *
 * This settles the case neither lexical similarity nor maturity can. PyPI's
 * `mcp` publishes from github.com/modelcontextprotocol/python-sdk and npm's
 * `@modelcontextprotocol/sdk` from github.com/modelcontextprotocol/typescript-sdk
 * — the same organisation, so one is not impersonating the other. Likewise
 * `vuex` (vuejs/vuex) against `vue` (vuejs/core).
 *
 * It is deliberately narrower than maturity: `preact` (preactjs/preact) and
 * `react` (react/react) are different organisations, and preact is still
 * perfectly legitimate. Shared ownership proves innocence; separate ownership
 * proves nothing. The two checks cover different cases — maturity clears
 * established independent projects, ownership clears a project's own siblings
 * even when they were published last week and have no history yet.
 */

/** Hosts whose first path segment is the owning account or organisation. */
const KNOWN_FORGES = new Set([
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "codeberg.org",
  "gitee.com",
  "git.sr.ht",
]);

/**
 * Reduce a repository URL to `host/owner`, or undefined when it is not a
 * recognisable forge URL.
 *
 * Handles the shapes registries actually return: `git+https://…​.git`,
 * plain https, `git://`, and scp-style `git@host:owner/repo`.
 */
export function repositoryOwner(url: string | undefined): string | undefined {
  if (!url) return undefined;
  let s = url.trim();
  if (!s) return undefined;

  // scp-style: git@github.com:owner/repo.git
  const scp = s.match(/^[\w.-]+@([\w.-]+):(.+)$/);
  if (scp) s = `https://${scp[1]}/${scp[2]}`;

  // Strip VCS prefixes and suffixes: git+https://…, …​.git
  s = s.replace(/^git\+/, "").replace(/\.git($|[?#])/, "$1");
  if (s.startsWith("git://")) s = `https://${s.slice("git://".length)}`;
  if (!/^https?:\/\//i.test(s)) s = `https://${s}`;

  let parsed: URL;
  try {
    parsed = new URL(s);
  } catch {
    return undefined;
  }

  const host = parsed.hostname.toLowerCase().replace(/^www\./, "");
  if (!KNOWN_FORGES.has(host)) return undefined;

  const owner = parsed.pathname.split("/").filter(Boolean)[0];
  if (!owner) return undefined;

  return `${host}/${owner.toLowerCase()}`;
}

/**
 * Whether two packages publish from the same organisation.
 *
 * Returns false when either repository is unknown: absent data is not evidence
 * of shared ownership, and must not clear a finding.
 */
export function sameRepositoryOwner(
  a: string | undefined,
  b: string | undefined,
): boolean {
  const ownerA = repositoryOwner(a);
  const ownerB = repositoryOwner(b);
  if (!ownerA || !ownerB) return false;
  return ownerA === ownerB;
}
