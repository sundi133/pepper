import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, requireRole } from "@/lib/auth-guard";
import { scanQueue } from "@/lib/queue";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;

  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      project: { select: { name: true, organizationId: true } },
      artifacts: { select: { type: true, objectKey: true, size: true } },
      _count: { select: { findings: true } },
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  return NextResponse.json(scan);
}

export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;

  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      id: true,
      jobId: true,
      status: true,
      project: { select: { organizationId: true } },
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const gate = await requireRole(scan.project.organizationId, "DEVELOPER");
  if ("error" in gate) return gate.error;

  if (scan.jobId && (scan.status === "QUEUED" || scan.status === "RUNNING")) {
    try {
      const job = await scanQueue.getJob(scan.jobId);
      if (job) await job.remove();
    } catch {
      // Job may already be gone or processing
    }
  }

  await prisma.scan.delete({ where: { id: scanId } });

  return NextResponse.json({ success: true, scanId });
}
