/**
 * SAML SSO configuration for a single, org-wide IdP (on-prem model).
 *
 * All settings come from environment variables (see .env.example). The feature
 * is inert unless ENABLE_SAML_SSO=true AND the IdP entry point + signing cert
 * are present, so a half-configured install never exposes a broken SSO button.
 */

import {
  ENABLE_SAML_SSO,
  SAML_ENTRY_POINT,
  SAML_IDP_CERT,
  SAML_ISSUER,
  SAML_GROUP_ATTR,
  SAML_EMAIL_ATTR,
  SAML_NAME_ATTR,
  SAML_ROLE_MAP,
  SAML_DEFAULT_ROLE,
  SAML_DEFAULT_ORG_SLUG,
  SAML_WANT_ASSERTIONS_SIGNED,
} from "@/lib/constants";
import { isRole, parseRoleMap, type Role } from "./role-mapping";

/** Base URL of this Pepper install, trailing slash stripped. */
export function appBaseUrl(): string {
  const url = process.env.NEXTAUTH_URL?.trim() || "http://localhost:3000";
  return url.replace(/\/+$/, "");
}

export function samlAcsUrl(): string {
  return `${appBaseUrl()}/api/auth/saml/acs`;
}

/** SP entity id (issuer). Defaults to the metadata URL, a common convention. */
export function samlIssuer(): string {
  return SAML_ISSUER.trim() || `${appBaseUrl()}/api/auth/saml/metadata`;
}

/** One or more IdP signing certs (comma-separated env → array for rotation). */
/**
 * Normalize a certificate to PEM. IdP metadata (and most copy-paste flows) give
 * the bare base64 body of the X509Certificate; node-saml requires full PEM, so
 * wrap a headerless body in BEGIN/END lines at 64 chars. A value that is already
 * PEM is returned unchanged.
 */
function toPem(cert: string): string {
  const c = cert.trim();
  if (c.includes("BEGIN CERTIFICATE")) return c;
  const body = c.replace(/\s+/g, "");
  const wrapped = body.match(/.{1,64}/g)?.join("\n") ?? body;
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`;
}

function idpCerts(): string[] {
  return SAML_IDP_CERT.split(",")
    .map((c) => c.trim())
    .filter(Boolean)
    .map(toPem);
}

/**
 * True only when SSO is switched on and minimally configured. Every entry point
 * (login route, provider registration, login button) checks this, so partial
 * configuration cannot brick normal login.
 */
export function isSamlEnabled(): boolean {
  return (
    ENABLE_SAML_SSO &&
    SAML_ENTRY_POINT.trim().length > 0 &&
    idpCerts().length > 0
  );
}

export interface SamlRuntimeConfig {
  /** Options passed straight to `new SAML(...)` from @node-saml/node-saml. */
  saml: {
    entryPoint: string;
    issuer: string;
    callbackUrl: string;
    idpCert: string | string[];
    wantAssertionsSigned: boolean;
    wantAuthnResponseSigned: boolean;
    audience: string | false;
    identifierFormat: string | null;
  };
  emailAttr: string;
  nameAttr: string;
  groupAttr: string;
  roleMap: Record<string, Role>;
  defaultRole: Role;
  defaultOrgSlug: string;
}

/**
 * Build the runtime SAML config, or throw if enabled-but-misconfigured. Callers
 * gate on isSamlEnabled() first; this throw is the belt-and-braces guard.
 */
export function getSamlConfig(): SamlRuntimeConfig {
  if (!isSamlEnabled()) {
    throw new Error("SAML SSO is not enabled or is not fully configured");
  }
  const certs = idpCerts();
  const defaultRole: Role = isRole(SAML_DEFAULT_ROLE)
    ? SAML_DEFAULT_ROLE
    : "VIEWER";

  return {
    saml: {
      entryPoint: SAML_ENTRY_POINT.trim(),
      issuer: samlIssuer(),
      callbackUrl: samlAcsUrl(),
      idpCert: certs.length === 1 ? certs[0] : certs,
      // Require a signature: on the assertion (secure default), or — when the
      // IdP signs only the response — on the response instead.
      wantAssertionsSigned: SAML_WANT_ASSERTIONS_SIGNED,
      wantAuthnResponseSigned: !SAML_WANT_ASSERTIONS_SIGNED,
      audience: samlIssuer(),
      identifierFormat: null,
    },
    emailAttr: SAML_EMAIL_ATTR.trim(),
    nameAttr: SAML_NAME_ATTR.trim(),
    groupAttr: SAML_GROUP_ATTR.trim() || "groups",
    roleMap: parseRoleMap(SAML_ROLE_MAP),
    defaultRole,
    defaultOrgSlug: SAML_DEFAULT_ORG_SLUG.trim(),
  };
}
