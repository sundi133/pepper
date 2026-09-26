import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, requireRole, getDefaultOrgId } from "@/lib/auth-guard";
import { writeAuditLog } from "@/lib/audit-log";

/**
 * POST /api/remediation/runs/[runId]/cancel — stop a run. A queued run is
 * cancelled immediately; a running one stops at the next step boundary and
 * never pushes.
 */
export async function POST(
  _req: NextRequest,
  { params }: { params: Promise<{ runId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const role = await requireRole(orgId, "DEVELOPER");
  if ("error" in role) return role.error;

  const { runId } = await params;
  const run = await prisma.remediationRun.findFirst({
    where: { id: runId, organizationId: orgId },
    select: { id: true, status: true, scanId: true },
  });
  if (!run) return NextResponse.json({ error: "Run not found" }, { status: 404 });

  if (run.status === "QUEUED") {
    const cancelled = await prisma.remediationRun.updateMany({
      where: { id: runId, status: "QUEUED" },
      data: { status: "CANCELLED", cancelRequested: true, completedAt: new Date() },
    });
    if (cancelled.count > 0) {
      await prisma.remediationItem.updateMany({
        where: { runId },
        data: { status: "SKIPPED", error: "Run cancelled" },
      });
    }
  } else if (run.status === "RUNNING") {
    await prisma.remediationRun.update({
      where: { id: runId },
      data: { cancelRequested: true },
    });
  } else {
    return NextResponse.json({ error: "The run has already finished." }, { status: 409 });
  }

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "remediation.cancelled",
    resource: "scan",
    resourceId: run.scanId,
    details: { runId },
  }).catch(() => undefined);

  return NextResponse.json({ ok: true });
}
