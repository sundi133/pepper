/**
 * Microsoft Entra ID sign-in (OpenID Connect) for one tenant.
 *
 * Off unless ENABLE_ENTRA_SSO=true and the tenant, client id and secret are
 * set. Single-tenant only: "common" / "organizations" / "consumers" are
 * refused, because accounts are matched to existing Pepper users by email,
 * which is only safe when every token comes from the customer's own tenant.
 *
 * Roles come from the ID token's app roles (`roles`) and security groups
 * (`groups`, object IDs) via ENTRA_ROLE_MAP. When a user is in too many groups
 * for the token (overage), the mapped groups are checked with Microsoft Graph
 * `checkMemberGroups`, which needs only the User.Read permission.
 */
import type { OAuthConfig } from "next-auth/providers/oauth";
import { logger } from "@/lib/logger";
import { isRole, mapSamlRole, normalizeGroups, parseRoleMap, type Role } from "@/lib/saml/role-mapping";

export const ENTRA_PROVIDER_ID = "entra";

const MULTI_TENANT = new Set(["common", "organizations", "consumers"]);
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** checkMemberGroups accepts at most 20 group ids per call. */
const GRAPH_BATCH = 20;

export interface EntraConfig {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  /** Sign-in host; national clouds use e.g. https://login.microsoftonline.us */
  authorityHost: string;
  /** Graph host for the overage lookup, e.g. https://graph.microsoft.us */
  graphUrl: string;
  overageLookup: boolean;
  roleMap: Record<string, Role>;
  defaultRole: Role;
  defaultOrgSlug: string;
  /** "raise": never lower an existing role. "exact": Entra is authoritative. */
  roleSync: "raise" | "exact";
  /** Refuse sign-in unless an app role or group in ENTRA_ROLE_MAP matches. */
  requireRole: boolean;
  allowGuests: boolean;
}

type Env = Record<string, string | undefined>;

const trimUrl = (v: string | undefined, fallback: string) => (v?.trim() || fallback).replace(/\/+$/, "");

/**
 * Entra settings from the environment: null when off, or an error message
 * when switched on but unusable (so a bad config never shows a broken button).
 */
export function readEntraConfig(env: Env = process.env): EntraConfig | { error: string } | null {
  if (env.ENABLE_ENTRA_SSO !== "true") return null;
  const tenantId = env.ENTRA_TENANT_ID?.trim() ?? "";
  const clientId = env.ENTRA_CLIENT_ID?.trim() ?? "";
  const clientSecret = env.ENTRA_CLIENT_SECRET?.trim() ?? "";
  if (!tenantId || !clientId || !clientSecret) {
    return { error: "ENTRA_TENANT_ID, ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET are required" };
  }
  if (MULTI_TENANT.has(tenantId.toLowerCase())) {
    return { error: `ENTRA_TENANT_ID must be your tenant's ID or domain, not "${tenantId}"` };
  }
  const defaultRole = env.ENTRA_DEFAULT_ROLE?.trim() || "VIEWER";
  return {
    tenantId,
    clientId,
    clientSecret,
    authorityHost: trimUrl(env.ENTRA_AUTHORITY_HOST, "https://login.microsoftonline.com"),
    graphUrl: trimUrl(env.ENTRA_GRAPH_URL, "https://graph.microsoft.com"),
    overageLookup: env.ENTRA_GROUP_OVERAGE_LOOKUP !== "false",
    roleMap: parseRoleMap(env.ENTRA_ROLE_MAP),
    defaultRole: isRole(defaultRole) ? defaultRole : "VIEWER",
    defaultOrgSlug: env.ENTRA_DEFAULT_ORG_SLUG?.trim() ?? "",
    roleSync: env.ENTRA_ROLE_SYNC?.trim() === "exact" ? "exact" : "raise",
    requireRole: env.ENTRA_REQUIRE_ROLE === "true",
    allowGuests: env.ENTRA_ALLOW_GUESTS === "true",
  };
}

let warned = false;
/** The usable config, or null (logging a misconfiguration once). */
export function getEntraConfig(env: Env = process.env): EntraConfig | null {
  const cfg = readEntraConfig(env);
  if (cfg && "error" in cfg) {
    if (!warned) logger.warn({ error: cfg.error }, "Entra sign-in disabled: misconfigured");
    warned = true;
    return null;
  }
  return cfg;
}

export function isEntraEnabled(): boolean {
  return getEntraConfig() !== null;
}

export function entraIssuer(cfg: EntraConfig): string {
  return `${cfg.authorityHost}/${cfg.tenantId}/v2.0`;
}

/** ID token claims Pepper reads. */
export interface EntraClaims {
  sub: string;
  oid?: string;
  tid?: string;
  email?: string;
  preferred_username?: string;
  upn?: string;
  name?: string;
  roles?: string[] | string;
  groups?: string[] | string;
  hasgroups?: boolean | string;
  _claim_names?: { groups?: string };
  /** Present for guests (B2B): the account's home identity provider. */
  idp?: string;
  /** Optional claim: 1 = guest. */
  acct?: number | string;
}

/** The email Pepper matches accounts on: `email`, else the UPN. */
export function entraEmail(claims: EntraClaims): string | null {
  for (const v of [claims.email, claims.preferred_username, claims.upn]) {
    const s = v?.trim().toLowerCase();
    if (s && s.includes("@")) return s;
  }
  return null;
}

export function isEntraGuest(claims: EntraClaims): boolean {
  return Boolean(claims.idp) || String(claims.acct ?? "") === "1";
}

export function hasGroupsOverage(claims: EntraClaims): boolean {
  if (claims.groups !== undefined) return false;
  return Boolean(claims._claim_names?.groups) || claims.hasgroups === true || claims.hasgroups === "true";
}

/** The NextAuth provider (OIDC discovery, PKCE + state + nonce, ID token validated). */
export function entraProvider(cfg: EntraConfig): OAuthConfig<EntraClaims> {
  return {
    id: ENTRA_PROVIDER_ID,
    name: "Microsoft",
    type: "oauth",
    wellKnown: `${entraIssuer(cfg)}/.well-known/openid-configuration`,
    // User.Read lets the overage lookup call Graph /me/checkMemberGroups.
    authorization: { params: { scope: "openid profile email User.Read" } },
    idToken: true,
    checks: ["pkce", "state", "nonce"],
    clientId: cfg.clientId,
    clientSecret: cfg.clientSecret,
    // Safe only because the issuer is pinned to one tenant (see header).
    allowDangerousEmailAccountLinking: true,
    profile(claims) {
      return {
        id: claims.oid ?? claims.sub,
        name: claims.name ?? null,
        email: entraEmail(claims),
        image: null,
      };
    },
  };
}

type Fetch = typeof fetch;

/** Which of `groupIds` the signed-in user belongs to (transitively). */
async function checkMemberGroups(cfg: EntraConfig, accessToken: string, groupIds: string[], fetchImpl: Fetch): Promise<string[]> {
  const found: string[] = [];
  for (let i = 0; i < groupIds.length; i += GRAPH_BATCH) {
    const res = await fetchImpl(`${cfg.graphUrl}/v1.0/me/checkMemberGroups`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ groupIds: groupIds.slice(i, i + GRAPH_BATCH) }),
    });
    if (!res.ok) throw new Error(`Graph checkMemberGroups failed (${res.status})`);
    const data = (await res.json()) as { value?: string[] };
    found.push(...(data.value ?? []));
  }
  return found;
}

export type EntraAccess =
  | { allowed: true; role: Role; matched: string[] }
  | { allowed: false; reason: "tenant" | "guest" | "no_email" | "no_role" };

/**
 * Decide whether this Entra user may sign in, and with which role. The
 * highest-privilege matching app role / group wins; the default role applies
 * when nothing matches (unless ENTRA_REQUIRE_ROLE refuses sign-in).
 */
export async function resolveEntraAccess(
  claims: EntraClaims,
  accessToken: string | undefined,
  cfg: EntraConfig,
  fetchImpl: Fetch = fetch,
): Promise<EntraAccess> {
  if (GUID.test(cfg.tenantId) && claims.tid && claims.tid.toLowerCase() !== cfg.tenantId.toLowerCase()) {
    return { allowed: false, reason: "tenant" };
  }
  if (!cfg.allowGuests && isEntraGuest(claims)) return { allowed: false, reason: "guest" };
  if (!entraEmail(claims)) return { allowed: false, reason: "no_email" };

  const values = [...normalizeGroups(claims.roles), ...normalizeGroups(claims.groups)];
  if (hasGroupsOverage(claims)) {
    const mappedGroups = Object.keys(cfg.roleMap).filter((k) => GUID.test(k));
    if (cfg.overageLookup && accessToken && mappedGroups.length > 0) {
      try {
        values.push(...(await checkMemberGroups(cfg, accessToken, mappedGroups, fetchImpl)));
      } catch (err) {
        logger.warn({ err }, "Entra groups overage: Graph lookup failed; only app roles apply");
      }
    } else if (mappedGroups.length > 0) {
      logger.warn("Entra groups overage: group lookup is off; only app roles apply");
    }
  }
  const matched = [...new Set(values.filter((v) => cfg.roleMap[v]))];
  if (cfg.requireRole && matched.length === 0) return { allowed: false, reason: "no_role" };
  return { allowed: true, role: mapSamlRole(matched, cfg), matched };
}
