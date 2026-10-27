import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getActiveOrgId } from "@/lib/auth-guard";

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

  const limit = Math.min(Math.max(Number(searchParams.get("limit")) || 30, 1), 100);
  const cursor = searchParams.get("cursor");
  const unreadOnly = searchParams.get("unread") === "true";
  const scope = { userId, organizationId: orgId };

  // Fetch one extra row to learn whether another page exists.
  const [rows, unreadCount] = await Promise.all([
    prisma.notification.findMany({
      where: { ...scope, ...(unreadOnly ? { read: false } : {}) },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: limit + 1,
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
    prisma.notification.count({ where: { ...scope, read: false } }),
  ]);

  const hasMore = rows.length > limit;
  const notifications = hasMore ? rows.slice(0, limit) : rows;
  const nextCursor = hasMore ? notifications[notifications.length - 1].id : null;

  return NextResponse.json({ notifications, unreadCount, nextCursor });
}

/** Deletes every read notification for the signed-in user in the active org. */
export async function DELETE(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { searchParams } = new URL(req.url);
  if (searchParams.get("read") !== "true") {
    return NextResponse.json({ error: "Only read=true is supported" }, { status: 400 });
  }

  const result = await prisma.notification.deleteMany({
    where: { userId: auth.session.user.id, organizationId: orgId, read: true },
  });

  return NextResponse.json({ deleted: result.count });
}
