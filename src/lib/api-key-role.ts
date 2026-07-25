import { ROLE_HIERARCHY } from "./constants";

export type Role = "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER";

/**
 * Ceiling on what an API key may do, regardless of who created it.
 *
 * ApiKey rows carry no role of their own, so one has to be chosen. Keys exist
 * for CI, IDE and pre-commit clients — creating scans, reading findings,
 * downloading artifacts — all of which need DEVELOPER at most. Capping here
 * means a long-lived credential sitting in a CI config can never change team
 * membership, delete scans or alter policy, even when an ADMIN issued it.
 */
export const MAX_API_KEY_ROLE: Role = "DEVELOPER";

/**
 * The role an API key may exercise: the lower of its creator's current role and
 * the cap. A key issued by an ADMIN acts as a DEVELOPER; a key issued by a
 * VIEWER stays a VIEWER and still cannot start scans.
 */
export function effectiveApiKeyRole(creatorRole: string): Role {
  const creatorRank = ROLE_HIERARCHY[creatorRole];
  // An unrecognised role is not assumed to be privileged.
  if (typeof creatorRank !== "number") return "VIEWER";

  return creatorRank >= ROLE_HIERARCHY[MAX_API_KEY_ROLE]
    ? MAX_API_KEY_ROLE
    : (creatorRole as Role);
}
