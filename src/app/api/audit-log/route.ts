import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { queryAuditLog } from "@/lib/audit-log";
import { parseAuditFilters } from "@/lib/audit-export";

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  // Holds user emails and IP addresses: security staff and admins only.
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const url = new URL(req.url);
  const cursor = url.searchParams.get("cursor") || undefined;
  const limit = url.searchParams.get("limit");
  const parsed = parseAuditFilters(url.searchParams);
  if ("error" in parsed) {
    return NextResponse.json({ error: parsed.error }, { status: 400 });
  }

  const { rows, nextCursor } = await queryAuditLog({
    organizationId: orgId,
    cursor,
    ...parsed.filters,
    limit: limit ? Math.min(parseInt(limit, 10) || 50, 200) : 50,
  });

  // Hydrate userIds -> name/email
  const userIds = Array.from(
    new Set(rows.map((r) => r.userId).filter((x): x is string => !!x)),
  );
  const users = userIds.length
    ? await prisma.user.findMany({
        where: { id: { in: userIds } },
        select: { id: true, name: true, email: true },
      })
    : [];
  const userMap = new Map(users.map((u) => [u.id, u]));

  return NextResponse.json({
    entries: rows.map((r) => ({
      id: r.id,
      action: r.action,
      resource: r.resource,
      resourceId: r.resourceId,
      details: r.details,
      ipAddress: r.ipAddress,
      createdAt: r.createdAt,
      user: r.userId
        ? {
            id: r.userId,
            name: userMap.get(r.userId)?.name || null,
            email: userMap.get(r.userId)?.email || null,
          }
        : null,
    })),
    nextCursor,
  });
}
