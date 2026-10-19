/**
 * Entra ID (Azure AD) service principal tokens for Azure DevOps Services
 * (docs/PR_REVIEW_PROVIDERS_SPEC.md §1.2): client credentials, cached in memory
 * until shortly before they expire, never stored. Errors never contain the
 * client secret.
 */

/** The Azure DevOps resource; `/.default` asks for the app's granted access. */
export const AZURE_DEVOPS_SCOPE = "499b84ac-1321-427f-aa17-267ca6975798/.default";
const REFRESH_MARGIN_MS = 5 * 60_000;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface ServicePrincipal {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export class EntraTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EntraTokenError";
  }
}

const cache = new Map<string, { token: string; expiresAt: number }>();

export function clearEntraTokenCache(): void {
  cache.clear();
}

/** Tenant: a GUID or a domain such as contoso.onmicrosoft.com. */
export function validServicePrincipalIds(sp: Pick<ServicePrincipal, "tenantId" | "clientId">): string | null {
  if (!GUID.test(sp.clientId.trim())) return "The client (application) ID must be a GUID.";
  const t = sp.tenantId.trim();
  if (!GUID.test(t) && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t)) return "The tenant ID must be a GUID or a domain (for example contoso.onmicrosoft.com).";
  return null;
}

export async function getEntraAccessToken(sp: ServicePrincipal, fetchImpl: typeof fetch = fetch, now = Date.now()): Promise<string> {
  const key = `${sp.tenantId}|${sp.clientId}`;
  const hit = cache.get(key);
  if (hit && hit.expiresAt - REFRESH_MARGIN_MS > now) return hit.token;

  const bad = validServicePrincipalIds(sp);
  if (bad) throw new EntraTokenError(bad);
  let res: Response;
  try {
    res = await fetchImpl(`https://login.microsoftonline.com/${encodeURIComponent(sp.tenantId.trim())}/oauth2/v2.0/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: sp.clientId.trim(),
        client_secret: sp.clientSecret,
        scope: AZURE_DEVOPS_SCOPE,
      }).toString(),
    });
  } catch (err) {
    throw new EntraTokenError(`Can't reach Entra ID: ${err instanceof Error ? err.message : String(err)}`);
  }
  let data: { access_token?: string; expires_in?: number; error?: string; error_description?: string } = {};
  try {
    data = await res.json();
  } catch {
    // reported below
  }
  if (!res.ok || !data.access_token) {
    // Entra's description names the problem (bad secret, app not found…) and never echoes the secret.
    const why = (data.error_description || data.error || `HTTP ${res.status}`).split("\n")[0].split(sp.clientSecret).join("[secret]");
    throw new EntraTokenError(`Entra ID refused the service principal: ${why.slice(0, 300)}`);
  }
  cache.set(key, { token: data.access_token, expiresAt: now + (data.expires_in ?? 3600) * 1000 });
  return data.access_token;
}

/**
 * Git environment that sends a bearer token as an HTTP header, without putting
 * it in the clone URL or on the command line (git ≥ 2.31 GIT_CONFIG_* variables).
 */
export function bearerGitEnv(token: string): Record<string, string> {
  return {
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "http.extraHeader",
    GIT_CONFIG_VALUE_0: `Authorization: Bearer ${token}`,
  };
}
