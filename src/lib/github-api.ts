const GITHUB_API = "https://api.github.com";

export interface GithubRepoInfo {
  default_branch: string;
  permissions?: {
    admin?: boolean;
    push?: boolean;
    pull?: boolean;
  };
}

type GithubApiErrorBody = {
  message?: string;
  errors?: Array<{ message?: string; code?: string }>;
};

/** Combine GitHub `message` and `errors[]` into one string for the UI. */
export function parseGithubErrorBody(data: unknown, raw: string): string {
  const body = data as GithubApiErrorBody;
  const parts: string[] = [];
  if (body?.message?.trim()) parts.push(body.message.trim());
  if (body?.errors?.length) {
    for (const e of body.errors) {
      const bit = [e.code, e.message].filter(Boolean).join(": ");
      if (bit.trim()) parts.push(bit.trim());
    }
  }
  if (parts.length) return parts.join(" — ");
  const trimmed = raw?.trim();
  if (trimmed && trimmed.startsWith("{")) {
    try {
      return parseGithubErrorBody(JSON.parse(trimmed) as unknown, "");
    } catch {
      /* use raw below */
    }
  }
  return trimmed?.slice(0, 500) ?? "";
}

export interface GithubRefResponse {
  object: { sha: string };
}

export interface GithubContentFile {
  type: string;
  encoding: string;
  content: string;
  sha: string;
}

function headers(token: string, extra?: HeadersInit): HeadersInit {
  return {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    Authorization: `Bearer ${token}`,
    ...extra,
  };
}

export async function githubGet<T>(
  token: string,
  path: string,
): Promise<{ ok: boolean; status: number; data: T; raw: string }> {
  const res = await fetch(`${GITHUB_API}${path}`, {
    headers: headers(token),
  });
  const raw = await res.text();
  let data: T = {} as T;
  try {
    if (raw) data = JSON.parse(raw) as T;
  } catch {
    /* empty */
  }
  return { ok: res.ok, status: res.status, data, raw };
}

export async function githubPost<T>(
  token: string,
  path: string,
  body: unknown,
): Promise<{ ok: boolean; status: number; data: T; raw: string }> {
  const res = await fetch(`${GITHUB_API}${path}`, {
    method: "POST",
    headers: headers(token, { "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  const raw = await res.text();
  let data: T = {} as T;
  try {
    if (raw) data = JSON.parse(raw) as T;
  } catch {
    /* empty */
  }
  return { ok: res.ok, status: res.status, data, raw };
}

export async function githubPut<T>(
  token: string,
  path: string,
  body: unknown,
): Promise<{ ok: boolean; status: number; data: T; raw: string }> {
  const res = await fetch(`${GITHUB_API}${path}`, {
    method: "PUT",
    headers: headers(token, { "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  const raw = await res.text();
  let data: T = {} as T;
  try {
    if (raw) data = JSON.parse(raw) as T;
  } catch {
    /* empty */
  }
  return { ok: res.ok, status: res.status, data, raw };
}

export async function githubDelete(
  token: string,
  path: string,
): Promise<{ ok: boolean; status: number; data: unknown; raw: string }> {
  const res = await fetch(`${GITHUB_API}${path}`, {
    method: "DELETE",
    headers: headers(token),
  });
  const raw = await res.text();
  let data: unknown = {};
  try {
    if (raw) data = JSON.parse(raw as string);
  } catch {
    /* empty */
  }
  return { ok: res.ok, status: res.status, data, raw };
}

/** Path in repo, e.g. `src/app/x.ts` → URL segment after /contents/ */
export function encodeRepoFilePath(filePath: string): string {
  return filePath
    .replace(/^[/\\]+/, "")
    .replace(/\\/g, "/")
    .split("/")
    .filter(Boolean)
    .map((s) => encodeURIComponent(s))
    .join("/");
}

/**
 * When GitHub returns "Resource not accessible by personal access token", the PAT is
 * recognized but not allowed for this repo/action. Replace with clearer guidance for the UI.
 */
export function explainGithubPatAccessError(
  apiMessage: string | undefined,
  owner: string,
  repo: string,
): string {
  const raw = (apiMessage || "").trim();
  if (/resource not accessible by personal access token/i.test(raw)) {
    return (
      `GitHub denied access on ${owner}/${repo} for this token. ` +
      "On a fine-grained PAT: add this repo and set Contents + Pull requests to Read and write. On a classic PAT: enable repo scope for private repos; authorize SAML SSO for the org if prompted. " +
      "Connect GitHub under Repositories (OAuth) or authorize when you click Open fix PR. The token needs permission to create branches and pull requests on this repository."
    );
  }
  if (/must have push access|write access to repository/i.test(raw)) {
    return (
      `GitHub rejected branch creation on ${owner}/${repo}: ${raw} ` +
      "Use a repo you can push to (your fork or a project where you are a collaborator with write access)."
    );
  }
  return raw || "GitHub request failed";
}

/** GitHub often returns only "Not Found" for missing files, wrong branch, or no repo access. */
export function humanizeGithubApiError(
  apiMessage: string | undefined,
  owner: string,
  repo: string,
  fallback: string,
): string {
  const raw = (apiMessage || "").trim();
  if (!raw || /^not found$/i.test(raw)) {
    return fallback;
  }
  return explainGithubPatAccessError(raw, owner, repo);
}

/** Path relative to repository root for GitHub Contents API. */
export function normalizeRepoFilePath(filePath: string): string {
  return filePath
    .trim()
    .replace(/\\/g, "/")
    .replace(/^\.\/+/, "")
    .replace(/^\/+/, "");
}

export async function fetchGithubRepo(
  token: string,
  owner: string,
  repo: string,
): Promise<{ ok: boolean; status: number; info?: GithubRepoInfo; message?: string }> {
  const r = await githubGet<GithubRepoInfo>(
    token,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
  );
  if (!r.ok) {
    return {
      ok: false,
      status: r.status,
      message: parseGithubErrorBody(r.data, r.raw),
    };
  }
  return { ok: true, status: r.status, info: r.data };
}

/** True when the token can create branches / open PRs on this repo. */
export function githubRepoAllowsPush(info: GithubRepoInfo): boolean {
  const p = info.permissions;
  if (!p) return true;
  return Boolean(p.push || p.admin);
}

export async function getHeadShaForBranch(
  token: string,
  owner: string,
  repo: string,
  branch: string,
): Promise<{ ok: boolean; sha?: string; message?: string }> {
  const r = await githubGet<GithubRefResponse>(
    token,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/refs/heads/${encodeURIComponent(branch)}`,
  );
  if (!r.ok) {
    return { ok: false, message: parseGithubErrorBody(r.data, r.raw) };
  }
  return { ok: true, sha: r.data.object?.sha };
}

export async function createBranchRef(
  token: string,
  owner: string,
  repo: string,
  branchName: string,
  sha: string,
): Promise<{ ok: boolean; status: number; message?: string }> {
  const r = await githubPost<unknown>(token, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/refs`, {
    ref: `refs/heads/${branchName}`,
    sha,
  });
  if (!r.ok) {
    return {
      ok: false,
      status: r.status,
      message: parseGithubErrorBody(r.data, r.raw),
    };
  }
  return { ok: true, status: r.status };
}

/** Create a branch ref; retries once if GitHub reports the ref already exists. */
export async function createBranchRefWithRetry(
  token: string,
  owner: string,
  repo: string,
  branchName: string,
  sha: string,
): Promise<{ ok: boolean; status: number; message?: string; branchName: string }> {
  let name = branchName;
  for (let attempt = 0; attempt < 2; attempt++) {
    const result = await createBranchRef(token, owner, repo, name, sha);
    if (result.ok) {
      return { ...result, branchName: name };
    }
    const msg = result.message ?? "";
    if (
      attempt === 0 &&
      result.status === 422 &&
      /already exists/i.test(msg)
    ) {
      const extra = Math.random().toString(36).slice(2, 8);
      name = `${branchName}-${extra}`.slice(0, 200);
      continue;
    }
    return { ...result, branchName: name };
  }
  return { ok: false, status: 502, message: "Failed to create branch", branchName: name };
}

export async function deleteBranchRef(
  token: string,
  owner: string,
  repo: string,
  branchName: string,
): Promise<{ ok: boolean; status: number; message?: string }> {
  const r = await githubDelete(
    token,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/refs/heads/${encodeURIComponent(branchName)}`,
  );
  if (!r.ok) {
    const err = r.data as { message?: string };
    return { ok: false, status: r.status, message: err?.message || r.raw };
  }
  return { ok: true, status: r.status };
}

export async function getFileOnRef(
  token: string,
  owner: string,
  repo: string,
  filePath: string,
  ref: string,
): Promise<{
  ok: boolean;
  status: number;
  content?: string;
  sha?: string;
  message?: string;
}> {
  const enc = encodeRepoFilePath(filePath);
  const r = await githubGet<GithubContentFile>(
    token,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${enc}?ref=${encodeURIComponent(ref)}`,
  );
  if (!r.ok) {
    return { ok: false, status: r.status, message: parseGithubErrorBody(r.data, r.raw) };
  }
  if (r.data.type !== "file" || r.data.encoding !== "base64") {
    return {
      ok: false,
      status: r.status,
      message: "Path is not a text file or uses unsupported encoding",
    };
  }
  const buf = Buffer.from(r.data.content.replace(/\s/g, ""), "base64");
  return {
    ok: true,
    status: r.status,
    content: buf.toString("utf8"),
    sha: r.data.sha,
  };
}

export function utf8ToGithubBase64(content: string): string {
  return Buffer.from(content, "utf8").toString("base64");
}

export async function putFileOnBranch(
  token: string,
  owner: string,
  repo: string,
  filePath: string,
  branch: string,
  message: string,
  newUtf8Content: string,
  previousBlobSha: string,
): Promise<{ ok: boolean; status: number; message?: string; commitSha?: string }> {
  const enc = encodeRepoFilePath(filePath);
  const r = await githubPut<{ commit?: { sha?: string } }>(
    token,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${enc}`,
    {
      message,
      content: utf8ToGithubBase64(newUtf8Content),
      sha: previousBlobSha,
      branch,
    },
  );
  if (!r.ok) {
    const err = r.data as { message?: string };
    return { ok: false, status: r.status, message: err?.message || r.raw };
  }
  return { ok: true, status: r.status, commitSha: r.data.commit?.sha };
}

export async function createPullRequest(
  token: string,
  owner: string,
  repo: string,
  input: { title: string; head: string; base: string; body: string },
): Promise<{
  ok: boolean;
  status: number;
  html_url?: string;
  number?: number;
  message?: string;
}> {
  const r = await githubPost<{ html_url?: string; number?: number; message?: string }>(
    token,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls`,
    {
      title: input.title,
      head: input.head,
      base: input.base,
      body: input.body,
    },
  );
  if (!r.ok) {
    const err = r.data as { message?: string };
    return { ok: false, status: r.status, message: err?.message || r.raw };
  }
  return {
    ok: true,
    status: r.status,
    html_url: r.data.html_url,
    number: r.data.number,
  };
}
