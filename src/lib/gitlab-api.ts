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
