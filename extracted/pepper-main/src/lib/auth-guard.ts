import { getServerSession } from "next-auth";
import { authOptions } from "./auth";
import { ROLE_HIERARCHY } from "./constants";
import { NextResponse } from "next/server";

type Role = "ADMIN" | "SECURITY" | "DEVELOPER" | "VIEWER";

export async function getSession() {
  return getServerSession(authOptions);
}

export async function requireAuth() {
  const session = await getSession();
  if (!session?.user?.id) {
    return {
      error: NextResponse.json({ error: "Unauthorized" }, { status: 401 }),
    };
  }
  return { session };
}

export async function requireRole(orgId: string, minRole: Role) {
  const session = await getSession();
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
