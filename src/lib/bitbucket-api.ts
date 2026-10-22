const BITBUCKET_API = "https://api.bitbucket.org/2.0";

export interface BitbucketAuth {
  username: string;
  appPassword: string;
}

function basicAuthHeader(auth: BitbucketAuth): string {
  const raw = `${auth.username}:${auth.appPassword}`;
  return `Basic ${Buffer.from(raw, "utf8").toString("base64")}`;
}

function jsonHeaders(auth: BitbucketAuth, extra?: HeadersInit): HeadersInit {
  return {
    Accept: "application/json",
    Authorization: basicAuthHeader(auth),
    ...extra,
  };
}

export interface BitbucketResponse<T> {
  ok: boolean;
  status: number;
  data: T;
  raw: string;
}

async function read<T>(res: Response): Promise<BitbucketResponse<T>> {
  const raw = await res.text();
  let data: T = {} as T;
  try {
    if (raw) data = JSON.parse(raw) as T;
  } catch {
    /* not JSON — fine for diff endpoint etc */
  }
  return { ok: res.ok, status: res.status, data, raw };
}

export async function bitbucketGet<T>(
  auth: BitbucketAuth,
  path: string,
): Promise<BitbucketResponse<T>> {
  const res = await fetch(`${BITBUCKET_API}${path}`, {
    headers: jsonHeaders(auth),
  });
  return read<T>(res);
}

/** GET that returns the raw response body as text (used for /diff). */
export async function bitbucketGetText(
  auth: BitbucketAuth,
  path: string,
): Promise<{ ok: boolean; status: number; text: string }> {
  const res = await fetch(`${BITBUCKET_API}${path}`, {
    headers: {
      Accept: "text/plain",
      Authorization: basicAuthHeader(auth),
    },
  });
  const text = await res.text();
  return { ok: res.ok, status: res.status, text };
}

export async function bitbucketPost<T>(
  auth: BitbucketAuth,
  path: string,
  body: unknown,
): Promise<BitbucketResponse<T>> {
  const res = await fetch(`${BITBUCKET_API}${path}`, {
    method: "POST",
    headers: jsonHeaders(auth, { "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  return read<T>(res);
}

export async function bitbucketPut<T>(
  auth: BitbucketAuth,
  path: string,
  body: unknown,
): Promise<BitbucketResponse<T>> {
  const res = await fetch(`${BITBUCKET_API}${path}`, {
    method: "PUT",
    headers: jsonHeaders(auth, { "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  return read<T>(res);
}

/** Combine Bitbucket `error.message` and detail into one string for the UI. */
export function parseBitbucketErrorBody(
  data: unknown,
  raw: string,
): string {
  const body = data as { error?: { message?: string; detail?: string }; type?: string };
  const parts: string[] = [];
  if (body?.error?.message) parts.push(body.error.message);
  if (body?.error?.detail) parts.push(body.error.detail);
  if (parts.length) return parts.join(" — ");
  const trimmed = raw?.trim();
  return trimmed?.slice(0, 500) ?? "";
}
