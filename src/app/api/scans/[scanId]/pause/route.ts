import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";

export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { scanId } = await params;
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: { id: true, status: true },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  if (scan.status !== "RUNNING") {
    return NextResponse.json(
      { error: "Only running scans can be paused" },
      { status: 400 },
    );
  }

  await prisma.scan.update({
    where: { id: scanId },
    data: { status: "PAUSED" },
  });

  try {
    const { notifyScanLifecycleFromApi } = await import("@/lib/scan-notifications");
    await notifyScanLifecycleFromApi({
      scanId,
      organizationId: orgId,
      actorUserId: auth.session.user.id,
      type: "SCAN_PAUSED",
    });
  } catch (e) {
    console.error("Failed to record notification:", e);
  }

  return NextResponse.json({ scanId, status: "PAUSED" });
}
