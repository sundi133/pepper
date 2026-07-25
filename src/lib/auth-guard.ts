import { getServerSession, type Session } from "next-auth";
import { cache } from "react";
import { headers } from "next/headers";
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

/**
 * Resolve an API key into a session-shaped principal.
 *
 * Actions are attributed to the user who created the key, so `triggeredBy`,
 * notifications and the audit log continue to name a real person rather than an
 * anonymous credential.
 *
 * A key is only honoured while its creator still belongs to the organisation:
 * a credential must not outlive the access of the person who issued it, which
 * is what would otherwise happen when someone leaves the team.
 */
async function sessionFromApiKey(): Promise<Session | null> {
  let authorization: string | null = null;
  try {
    authorization = (await headers()).get("authorization");
  } catch {
    // No request context (e.g. called outside a route handler).
    return null;
  }
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

  // Never grant more than the creator currently has, nor more than the cap.
  const effectiveRole = effectiveApiKeyRole(membership.role);

  return {
    user: {
      id: membership.userId,
      memberships: [
        {
          organizationId: verified.organizationId,
          role: effectiveRole,
          organizationName: verified.organization?.name,
          organizationSlug: verified.organization?.slug,
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

export async function requireAuth() {
  const session = await resolvePrincipal();
  if (!session?.user?.id) {
    return {
      error: NextResponse.json({ error: "Unauthorized" }, { status: 401 }),
    };
  }
  return { session };
}

export async function requireRole(orgId: string, minRole: Role) {
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
