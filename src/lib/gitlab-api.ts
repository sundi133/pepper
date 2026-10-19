const DEFAULT_GITLAB_HOST = "https://gitlab.com";

export interface GitLabAuth {
  hostUrl: string;
  accessToken: string;
}

export interface GitLabResponse<T> {
  ok: boolean;
  status: number;
  data: T;
  raw: string;
}

function apiBase(auth: GitLabAuth): string {
  return `${auth.hostUrl.replace(/\/+$/, "")}/api/v4`;
}

function authHeaders(auth: GitLabAuth): HeadersInit {
  return {
    "Content-Type": "application/json",
    "PRIVATE-TOKEN": auth.accessToken,
  };
}

async function readResponse<T>(res: Response): Promise<GitLabResponse<T>> {
  const raw = await res.text();
  let data: T = {} as T;
  try {
    if (raw) data = JSON.parse(raw) as T;
  } catch {
    /* not JSON */
  }
  return { ok: res.ok, status: res.status, data, raw };
}

export async function gitlabGet<T>(
  auth: GitLabAuth,
  path: string,
): Promise<GitLabResponse<T>> {
  const res = await fetch(`${apiBase(auth)}${path}`, {
    headers: authHeaders(auth),
  });
  return readResponse<T>(res);
}

export async function gitlabPost<T>(
  auth: GitLabAuth,
  path: string,
  body: unknown,
): Promise<GitLabResponse<T>> {
  const res = await fetch(`${apiBase(auth)}${path}`, {
    method: "POST",
    headers: authHeaders(auth),
    body: JSON.stringify(body),
  });
  return readResponse<T>(res);
}

export async function gitlabPut<T>(
  auth: GitLabAuth,
  path: string,
  body: unknown,
): Promise<GitLabResponse<T>> {
  const res = await fetch(`${apiBase(auth)}${path}`, {
    method: "PUT",
    headers: authHeaders(auth),
    body: JSON.stringify(body),
  });
  return readResponse<T>(res);
}

export { DEFAULT_GITLAB_HOST };

/** Whether `repoUrl` is on the connection's GitLab host (same scheme, host and port). */
export function isOnGitLabHost(repoUrl: string, auth: Pick<GitLabAuth, "hostUrl">): boolean {
  try {
    return new URL(repoUrl).origin === new URL(auth.hostUrl).origin;
  } catch {
    return false;
  }
}

/**
 * Clone/push URL with the connection's token (`oauth2:<token>@`, accepted for
 * personal, group and project access tokens), or null when the repository is
 * on another host, so the token is never sent elsewhere. Never persist or log it.
 */
export function withGitLabCredentials(repoUrl: string, auth: GitLabAuth): string | null {
  const token = auth.accessToken.trim();
  if (!token || !isOnGitLabHost(repoUrl, auth)) return null;
  const u = new URL(repoUrl);
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  u.username = "oauth2";
  u.password = encodeURIComponent(token);
  return u.toString();
}

/** `group/sub/project` from a GitLab repository URL (without `.git`), or null. */
export function gitlabProjectPath(repoUrl: string, auth?: Pick<GitLabAuth, "hostUrl">): string | null {
  try {
    const u = new URL(repoUrl);
    let path = decodeURIComponent(u.pathname);
    // Self-managed GitLab under a relative URL root (https://host/gitlab/…).
    if (auth) {
      const root = new URL(auth.hostUrl).pathname.replace(/\/+$/, "");
      if (root && path.startsWith(`${root}/`)) path = path.slice(root.length);
    }
    path = path.replace(/^\/+|\/+$/g, "").replace(/\.git$/i, "");
    return /^[\w.-]+(?:\/[\w.-]+)+$/.test(path) && !path.split("/").includes("..") ? path : null;
  } catch {
    return null;
  }
}
