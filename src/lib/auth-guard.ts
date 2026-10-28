import { getServerSession, type Session } from "next-auth";
import { cache } from "react";
import { headers, cookies } from "next/headers";
import { authOptions } from "./auth";
import { ROLE_HIERARCHY } from "./constants";
import { verifyApiKey } from "./api-key";
import { effectiveApiKeyRole } from "./api-key-role";
import { prisma } from "./prisma";
import { NextResponse } from "next/server";

type Role = "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER";

export async function getSession() {
  return getServerSession(authOptions);
}

/** The caller behind a bearer API key: the key's creator, acting in the key's organization. */
export interface ApiKeyPrincipal {
  apiKeyId: string;
  userId: string;
  organizationId: string;
  /** The creator's current role, capped for API keys (see effectiveApiKeyRole). */
  role: Role;
  organizationName?: string;
  organizationSlug?: string;
}

/**
 * Resolve an `Authorization` header value carrying an API key into the
 * principal it acts as, or null when the key is missing, unknown or expired.
 *
 * Actions are attributed to the user who created the key, so `triggeredBy`,
 * notifications and the audit log continue to name a real person rather than an
 * anonymous credential.
 *
 * A key is only honoured while its creator still belongs to the organisation:
 * a credential must not outlive the access of the person who issued it, which
 * is what would otherwise happen when someone leaves the team.
 */
export async function resolveApiKeyPrincipal(
  authorization: string | null | undefined,
): Promise<ApiKeyPrincipal | null> {
  if (!authorization) return null;

  const verified = await verifyApiKey(authorization);
  if (!verified) return null;

  const key = await prisma.apiKey.findUnique({
    where: { id: verified.apiKeyId },
    select: { createdBy: true },
  });
  if (!key?.createdBy) return null;

  const membership = await prisma.orgMember.findFirst({
    where: {
      userId: key.createdBy,
      organizationId: verified.organizationId,
    },
    select: { userId: true, role: true },
  });
  if (!membership) return null;

  return {
    apiKeyId: verified.apiKeyId,
    userId: membership.userId,
    organizationId: verified.organizationId,
    // Never grant more than the creator currently has, nor more than the cap.
    role: effectiveApiKeyRole(membership.role),
    organizationName: verified.organization?.name,
    organizationSlug: verified.organization?.slug,
  };
}

/** Resolve the request's bearer API key into a session-shaped principal. */
async function sessionFromApiKey(): Promise<Session | null> {
  let authorization: string | null = null;
  try {
    authorization = (await headers()).get("authorization");
  } catch {
    // No request context (e.g. called outside a route handler).
    return null;
  }
  if (!authorization) return null;

  const principal = await resolveApiKeyPrincipal(authorization);
  if (!principal) return null;

  return {
    user: {
      id: principal.userId,
      memberships: [
        {
          organizationId: principal.organizationId,
          role: principal.role,
          organizationName: principal.organizationName,
          organizationSlug: principal.organizationSlug,
        },
      ],
    },
    expires: "",
  } as Session;
}

/**
 * The caller behind this request: a browser session, or a bearer API key.
 *
 * Cached per request so guards that run in sequence (requireAuth then
 * requireRole) do not verify the key twice.
 */
export const resolvePrincipal = cache(async (): Promise<Session | null> => {
  const session = await getSession();
  if (session?.user?.id) return session;
  return sessionFromApiKey();
});

/**
 * Declared explicitly: the inferred type would add `error?: undefined` to the
 * success case, so `"error" in auth` could never narrow and every route's
 * return type picked up `| undefined`.
 */
export type AuthResult = { error: NextResponse } | { session: Session };

export async function requireAuth(): Promise<AuthResult> {
  const session = await resolvePrincipal();
  if (!session?.user?.id) {
    return {
      error: NextResponse.json({ error: "Unauthorized" }, { status: 401 }),
    };
  }
  return { session };
}

type Membership = NonNullable<Session["user"]["memberships"]>[number];

/** Explicit for the same reason as AuthResult. */
export type RoleResult = { error: NextResponse } | { session: Session; membership: Membership };

export async function requireRole(orgId: string, minRole: Role): Promise<RoleResult> {
  const session = await resolvePrincipal();
  if (!session?.user?.id) {
    return {
      error: NextResponse.json({ error: "Unauthorized" }, { status: 401 }),
    };
  }

  const membership = session.user.memberships?.find(
    (m) => m.organizationId === orgId,
  );
  if (
    !membership ||
    ROLE_HIERARCHY[membership.role] < ROLE_HIERARCHY[minRole]
  ) {
    return {
      error: NextResponse.json({ error: "Forbidden" }, { status: 403 }),
    };
  }

  return { session, membership };
}

export function getDefaultOrgId(
  session: Awaited<ReturnType<typeof getSession>>,
): string | null {
  return session?.user?.memberships?.[0]?.organizationId ?? null;
}

/** Name of the httpOnly cookie that holds the user's selected active organisation. */
export const ACTIVE_ORG_COOKIE = "active_org";

/**
 * The organisation the user is currently working in, for request-scoped routes.
 *
 * A multi-org user selects an active org through the org switcher, which stores
 * the chosen id in the `active_org` cookie. Here we honour that selection, but
 * only after confirming the user is still a member of that org — the cookie is
 * attacker-controllable, so trusting it blindly would let someone read or write
 * another org's settings by forging the value (IDOR). When the cookie is unset,
 * malformed, or names an org the user does not belong to, we fall back to
 * `getDefaultOrgId` (the first membership), which is the pre-switcher behaviour,
 * so single-org users and non-switching sessions are completely unaffected.
 *
 * Callers must STILL apply their own membership/role checks against the returned
 * id (e.g. `requireRole`): this resolves which org is current, it does not grant
 * access to it.
 *
 * Outside a request context (no cookie store, e.g. the worker) this falls back
 * to the default org; scans resolve their org from `project.organizationId`, not
 * from here, so background processing is unaffected.
 */
export async function getActiveOrgId(
  session: Awaited<ReturnType<typeof getSession>>,
): Promise<string | null> {
  const memberships = session?.user?.memberships;
  if (!memberships || memberships.length === 0) return null;

  let selected: string | undefined;
  try {
    selected = (await cookies()).get(ACTIVE_ORG_COOKIE)?.value;
  } catch {
    // No request context (e.g. called from the worker) — use the default.
    selected = undefined;
  }

  if (selected && memberships.some((m) => m.organizationId === selected)) {
    return selected;
  }

  return getDefaultOrgId(session);
}
