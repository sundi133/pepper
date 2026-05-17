import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";

export async function POST() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const userId = auth.session.user.id;

  await prisma.notification.updateMany({
    where: { userId, organizationId: orgId, read: false },
    data: { read: true },
  });

  return NextResponse.json({ ok: true });
}
