import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { scanQueue } from "@/lib/queue";

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
    select: { id: true, status: true, jobId: true },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  if (
    scan.status !== "QUEUED" &&
    scan.status !== "RUNNING" &&
    scan.status !== "PAUSED"
  ) {
    return NextResponse.json(
      { error: "Scan is not in a stoppable state" },
      { status: 400 },
    );
  }

  if (scan.jobId) {
    try {
      const job = await scanQueue.getJob(scan.jobId);
      if (job) await job.remove();
    } catch {
      // Active jobs cannot always be removed; the worker exits on STOPPED.
    }
  }

  await prisma.scan.update({
    where: { id: scanId },
    data: { status: "STOPPED", completedAt: new Date() },
  });

  return NextResponse.json({
    scanId,
    status: "STOPPED",
    reportUrl: `/api/scans/${scanId}/findings/export?format=html`,
  });
}
