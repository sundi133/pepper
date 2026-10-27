import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getActiveOrgId } from "@/lib/auth-guard";

const PAGE_SIZE = 50;

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const userId = auth.session.user.id;
  const { searchParams } = new URL(req.url);
  const summary = searchParams.get("summary");

  if (summary === "unread") {
    const unreadCount = await prisma.notification.count({
      where: { userId, organizationId: orgId, read: false },
    });
    return NextResponse.json({ unreadCount });
  }

  const unreadOnly = searchParams.get("filter") === "unread";
  const cursor = searchParams.get("cursor");

  const [rows, unreadCount, total] = await Promise.all([
    prisma.notification.findMany({
      where: { userId, organizationId: orgId, ...(unreadOnly ? { read: false } : {}) },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: PAGE_SIZE + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      select: {
        id: true,
        type: true,
        title: true,
        body: true,
        read: true,
        scanId: true,
        createdAt: true,
      },
    }),
    prisma.notification.count({
      where: { userId, organizationId: orgId, read: false },
    }),
    prisma.notification.count({ where: { userId, organizationId: orgId } }),
  ]);

  const hasMore = rows.length > PAGE_SIZE;
  const notifications = hasMore ? rows.slice(0, PAGE_SIZE) : rows;

  return NextResponse.json({
    notifications,
    unreadCount,
    total,
    nextCursor: hasMore ? notifications[notifications.length - 1].id : null,
  });
}

/** `DELETE /api/notifications?scope=read` clears the caller's read notifications. */
export async function DELETE(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const scope = new URL(req.url).searchParams.get("scope");
  if (scope !== "read") {
    return NextResponse.json({ error: "Use ?scope=read" }, { status: 400 });
  }

  const result = await prisma.notification.deleteMany({
    where: { userId: auth.session.user.id, organizationId: orgId, read: true },
  });
  return NextResponse.json({ ok: true, deleted: result.count });
}
