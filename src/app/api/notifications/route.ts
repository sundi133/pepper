import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
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

  const [notifications, unreadCount] = await Promise.all([
    prisma.notification.findMany({
      where: { userId, organizationId: orgId },
      orderBy: { createdAt: "desc" },
      take: 100,
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
  ]);

  return NextResponse.json({ notifications, unreadCount });
}
