/**
 * Lazily-built @node-saml/node-saml instance for the single configured IdP,
 * plus helpers to pull a normalized identity out of a validated assertion.
 */

import { SAML } from "@node-saml/node-saml";
import { getSamlConfig, type SamlRuntimeConfig } from "./config";
import { normalizeGroups } from "./role-mapping";

let cached: { saml: SAML; cfg: SamlRuntimeConfig } | null = null;

export function getSamlClient(): { saml: SAML; cfg: SamlRuntimeConfig } {
  if (cached) return cached;
  const cfg = getSamlConfig();
  const saml = new SAML(cfg.saml);
  cached = { saml, cfg };
  return cached;
}

/** Reset the cached client (used in tests / after config changes). */
export function resetSamlClient(): void {
  cached = null;
}

// Common attribute-name fallbacks used by major IdPs when no explicit
// SAML_*_ATTR override is configured.
const EMAIL_KEYS = [
  "email",
  "mail",
  "emailaddress",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
  "urn:oid:0.9.2342.19200300.100.1.3",
];
const NAME_KEYS = [
  "displayName",
  "name",
  "cn",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname",
];

type Profile = Record<string, unknown> & { nameID?: string | null };

function firstString(profile: Profile, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = profile[k];
    if (typeof v === "string" && v.trim()) return v.trim();
    if (Array.isArray(v) && typeof v[0] === "string" && v[0].trim()) {
      return v[0].trim();
    }
  }
  return undefined;
}

export interface SamlIdentity {
  email: string;
  name: string | null;
  groups: string[];
}

/**
 * Resolve email, display name, and group claims from a node-saml profile.
 * The configured attribute names win; otherwise common IdP conventions are
 * tried, with the SAML nameID as the last resort for email.
 */
export function extractSamlIdentity(
  profile: Profile,
  cfg: SamlRuntimeConfig,
): SamlIdentity {
  const email =
    (cfg.emailAttr && firstString(profile, [cfg.emailAttr])) ||
    firstString(profile, EMAIL_KEYS) ||
    (typeof profile.nameID === "string" && profile.nameID.includes("@")
      ? profile.nameID.trim()
      : undefined) ||
    "";

  const name =
    (cfg.nameAttr && firstString(profile, [cfg.nameAttr])) ||
    firstString(profile, NAME_KEYS) ||
    joinNames(profile) ||
    null;

  const groups = normalizeGroups(profile[cfg.groupAttr]);

  return { email: email.toLowerCase(), name, groups };
}

function joinNames(profile: Profile): string | undefined {
  const given = firstString(profile, [
    "givenName",
    "firstName",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
  ]);
  const family = firstString(profile, [
    "surname",
    "lastName",
    "sn",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
  ]);
  const joined = [given, family].filter(Boolean).join(" ").trim();
  return joined || undefined;
}
