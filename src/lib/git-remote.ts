/**
 * Git remote URLs in one comparable form, `host/path` in lower case:
 *
 *   https://user:token@github.com/Org/Repo.git   → github.com/org/repo
 *   git@github.com:Org/Repo.git                  → github.com/org/repo
 *   ssh://git@host:7999/team/repo.git            → host/team/repo
 *   https://org@dev.azure.com/org/proj/_git/repo → dev.azure.com/org/proj/repo
 *   org@vs-ssh.visualstudio.com:v3/org/proj/repo → dev.azure.com/org/proj/repo
 *
 * Credentials, scheme, port, `.git` and trailing slashes never matter. Shared
 * by the server (`/api/ide/repository`) and the IDE language server, so it has
 * no dependencies.
 */
export function normalizeGitRemote(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let s = raw.trim();
  if (!s) return null;

  let host = "";
  let path = "";
  const scp = /^(?:[^@/\s]+@)?([^:/\s]+):(?!\/\/)(.+)$/.exec(s); // git@host:owner/repo
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && scp) {
    host = scp[1];
    path = scp[2];
  } else {
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
    try {
      const u = new URL(s);
      host = u.hostname;
      path = decodeURIComponent(u.pathname);
    } catch {
      return null;
    }
  }

  host = host.toLowerCase().replace(/^www\./, "");
  path = path.replace(/^\/+|\/+$/g, "").replace(/\.git$/i, "").replace(/\/+$/, "");

  // Azure DevOps: one canonical form for HTTPS, legacy visualstudio.com and SSH.
  if (host === "ssh.dev.azure.com" || host === "vs-ssh.visualstudio.com") {
    path = path.replace(/^v3\//i, "");
    host = "dev.azure.com";
  } else if (host.endsWith(".visualstudio.com")) {
    path = `${host.split(".")[0]}/${path}`;
    host = "dev.azure.com";
  }
  if (host === "dev.azure.com") path = path.replace(/\/_git\//i, "/");

  if (!host || !path) return null;
  return `${host}/${path}`.toLowerCase();
}

/** Last path segment of a remote (the repository's own name). */
export function remoteRepoName(raw: string | null | undefined): string | null {
  const n = normalizeGitRemote(raw);
  return n ? n.split("/").pop() || null : null;
}
