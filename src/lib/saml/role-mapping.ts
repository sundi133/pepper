/**
 * Map a SAML user's IdP groups to a Pepper role.
 *
 * The IdP is authoritative: an org configures which group grants which role via
 * SAML_ROLE_MAP. When a user is in several mapped groups, the HIGHEST-privilege
 * role wins (ADMIN > SECURITY > DEVELOPER > VIEWER) so a broad "engineers" group
 * never downgrades someone who is also in "pepper-admins". When no group maps,
 * the configured default role is used.
 */

export type Role = "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER";

const ROLE_RANK: Record<Role, number> = {
  VIEWER: 0,
  DEVELOPER: 1,
  SECURITY: 2,
  ADMIN: 3,
};

const VALID_ROLES = new Set<string>(Object.keys(ROLE_RANK));

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && VALID_ROLES.has(value);
}

/**
 * Parse the SAML_ROLE_MAP JSON into a normalized `{ group: Role }` map.
 * Invalid entries (unknown roles, non-string values) are dropped; a malformed
 * document yields an empty map rather than throwing, so a bad config degrades
 * to "everyone gets the default role" instead of breaking login.
 */
export function parseRoleMap(raw: string | null | undefined): Record<string, Role> {
  if (!raw?.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {};
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const out: Record<string, Role> = {};
  for (const [group, role] of Object.entries(parsed as Record<string, unknown>)) {
    const g = group.trim();
    if (g && isRole(role)) out[g] = role;
  }
  return out;
}

/**
 * Resolve the effective role for a user, given their group claims.
 * `groups` may be a string, an array, or undefined (IdPs vary).
 */
export function mapSamlRole(
  groups: unknown,
  config: { roleMap: Record<string, Role>; defaultRole: Role },
): Role {
  const list = normalizeGroups(groups);
  let best: Role | null = null;
  for (const g of list) {
    const mapped = config.roleMap[g];
    if (mapped && (best === null || ROLE_RANK[mapped] > ROLE_RANK[best])) {
      best = mapped;
    }
  }
  return best ?? config.defaultRole;
}

/** The higher-privilege of two roles (ADMIN > SECURITY > DEVELOPER > VIEWER). */
export function higherRole(a: Role, b: Role): Role {
  return ROLE_RANK[a] >= ROLE_RANK[b] ? a : b;
}

/** Coerce an IdP group claim (string | array | scalar) into a string[]. */
export function normalizeGroups(groups: unknown): string[] {
  if (groups == null) return [];
  const arr = Array.isArray(groups) ? groups : [groups];
  return arr
    .map((g) => (typeof g === "string" ? g.trim() : String(g).trim()))
    .filter((g) => g.length > 0);
}
