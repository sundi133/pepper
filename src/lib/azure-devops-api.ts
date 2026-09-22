/**
 * Thin HTTP wrapper for the Azure DevOps REST API — both the hosted service
 * (Azure DevOps Services, `https://dev.azure.com/{organization}`) and the
 * self-hosted product (Azure DevOps Server, `https://{host}[/{virtualDir}]/
 * {collection}`).
 *
 * Auth: Personal Access Token (PAT) sent as Basic auth with an empty
 * username — the de-facto convention used by every ADO client. ADO requires an
 * `api-version` query parameter on every request; we default to 7.1 (override
 * with AZURE_DEVOPS_API_VERSION — older Server releases need e.g. 6.0) and let
 * callers pass a different one when needed.
 */

const CLOUD_BASE = "https://dev.azure.com";
const DEFAULT_API_VERSION =
  process.env.AZURE_DEVOPS_API_VERSION?.trim() || "7.1";

export interface AzureDevOpsAuth {
  /**
   * The ADO organization (cloud, the `dev.azure.com/<org>` segment) or the
   * collection name (on-prem Azure DevOps Server).
   */
  organization: string;
  /** The Personal Access Token. */
  pat: string;
  /**
   * On-prem Azure DevOps Server base — the host and any virtual directory up to
   * (but not including) the collection, e.g. `https://tfs.company.com` or
   * `https://tfs.company.com/tfs`. Omitted/empty for the hosted service.
   */
  serverUrl?: string;
}

/** True when this connection targets a self-hosted Azure DevOps Server. */
export function isAzureDevOpsServer(auth: AzureDevOpsAuth): boolean {
  return Boolean(auth.serverUrl && auth.serverUrl.trim());
}

/**
 * The API/base URL for a connection, up to and including the org/collection:
 *   cloud  → https://dev.azure.com/{organization}
 *   server → {serverUrl}/{collection}
 * Everything the callers append (`/_apis/...`, `/{project}/_apis/...`) is
 * identical between the two, so only this prefix differs.
 */
export function azureApiBase(auth: AzureDevOpsAuth): string {
  const org = encodeURIComponent(auth.organization);
  if (isAzureDevOpsServer(auth)) {
    const host = auth.serverUrl!.trim().replace(/\/+$/, "");
    return `${host}/${org}`;
  }
  return `${CLOUD_BASE}/${org}`;
}

function basicAuthHeader(pat: string): string {
  return `Basic ${Buffer.from(`:${pat}`, "utf8").toString("base64")}`;
}

function buildUrl(
  auth: AzureDevOpsAuth,
  path: string,
  apiVersion = DEFAULT_API_VERSION,
): string {
  const base = azureApiBase(auth);
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
