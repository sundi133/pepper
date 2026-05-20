/**
 * Thin HTTP wrapper for the Azure DevOps Services REST API.
 *
 * Auth: Personal Access Token (PAT) sent as Basic auth with an empty
 * username — the de-facto convention used by every ADO client. Base URL
 * is `https://dev.azure.com/{organization}/`. ADO requires an `api-version`
 * query parameter on every request; we default to 7.1 and let callers pass
 * a different one when needed.
 */

const ADO_BASE = "https://dev.azure.com";
const DEFAULT_API_VERSION = "7.1";

export interface AzureDevOpsAuth {
  /** The ADO organization (the `dev.azure.com/<org>` segment). */
  organization: string;
  /** The Personal Access Token. */
  pat: string;
}

function basicAuthHeader(pat: string): string {
  return `Basic ${Buffer.from(`:${pat}`, "utf8").toString("base64")}`;
}

function buildUrl(
  auth: AzureDevOpsAuth,
  path: string,
  apiVersion = DEFAULT_API_VERSION,
): string {
  const base = `${ADO_BASE}/${encodeURIComponent(auth.organization)}`;
  const url = new URL(`${base}${path.startsWith("/") ? path : `/${path}`}`);
  if (!url.searchParams.has("api-version")) {
    url.searchParams.set("api-version", apiVersion);
  }
  return url.toString();
}

export interface AzureDevOpsResponse<T> {
  ok: boolean;
  status: number;
  data: T;
  raw: string;
}

async function readJson<T>(res: Response): Promise<AzureDevOpsResponse<T>> {
  const raw = await res.text();
  let data: T = {} as T;
  try {
    if (raw) data = JSON.parse(raw) as T;
  } catch {
    /* non-JSON body — fine for some endpoints */
  }
  return { ok: res.ok, status: res.status, data, raw };
}

export async function azureGet<T>(
  auth: AzureDevOpsAuth,
  path: string,
  apiVersion?: string,
): Promise<AzureDevOpsResponse<T>> {
  const res = await fetch(buildUrl(auth, path, apiVersion), {
    headers: {
      Accept: "application/json",
      Authorization: basicAuthHeader(auth.pat),
    },
  });
  return readJson<T>(res);
}

/** GET that returns raw text — used for `/diffs/commits` which returns JSON
 * but is sometimes called for other text payloads. Kept for symmetry. */
export async function azureGetText(
  auth: AzureDevOpsAuth,
  path: string,
  apiVersion?: string,
): Promise<{ ok: boolean; status: number; text: string }> {
  const res = await fetch(buildUrl(auth, path, apiVersion), {
    headers: {
      Accept: "text/plain, application/json",
      Authorization: basicAuthHeader(auth.pat),
    },
  });
  const text = await res.text();
  return { ok: res.ok, status: res.status, text };
}

export async function azurePost<T>(
  auth: AzureDevOpsAuth,
  path: string,
  body: unknown,
  apiVersion?: string,
): Promise<AzureDevOpsResponse<T>> {
  const res = await fetch(buildUrl(auth, path, apiVersion), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: basicAuthHeader(auth.pat),
    },
    body: JSON.stringify(body),
  });
  return readJson<T>(res);
}

export async function azurePatch<T>(
  auth: AzureDevOpsAuth,
  path: string,
  body: unknown,
  apiVersion?: string,
): Promise<AzureDevOpsResponse<T>> {
  const res = await fetch(buildUrl(auth, path, apiVersion), {
    method: "PATCH",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: basicAuthHeader(auth.pat),
    },
    body: JSON.stringify(body),
  });
  return readJson<T>(res);
}

export async function azurePut<T>(
  auth: AzureDevOpsAuth,
  path: string,
  body: unknown,
  apiVersion?: string,
): Promise<AzureDevOpsResponse<T>> {
  const res = await fetch(buildUrl(auth, path, apiVersion), {
    method: "PUT",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      Authorization: basicAuthHeader(auth.pat),
    },
    body: JSON.stringify(body),
  });
  return readJson<T>(res);
}

/** ADO error envelopes vary; combine the common shapes into one line. */
export function parseAzureErrorBody(data: unknown, raw: string): string {
  const body = data as {
    message?: string;
    typeKey?: string;
    value?: { Message?: string };
  };
  if (body?.message) return body.message;
  if (body?.value?.Message) return body.value.Message;
  const trimmed = raw?.trim();
  return trimmed?.slice(0, 500) ?? "";
}
