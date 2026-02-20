import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth-guard";
import { scanQueue } from "@/lib/queue";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> }
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;

  const scan = await prisma.scan.findUnique({ where: { id: scanId } });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  if (scan.status !== "QUEUED" && scan.status !== "RUNNING") {
    return NextResponse.json(
      { error: "Scan is not in a cancellable state" },
      { status: 400 }
    );
  }

  // Try to remove from queue
  if (scan.jobId) {
    try {
      const job = await scanQueue.getJob(scan.jobId);
      if (job) {
        await job.remove();
      }
    } catch {
      // Job might already be processing
    }
  }

  await prisma.scan.update({
    where: { id: scanId },
    data: { status: "CANCELLED", completedAt: new Date() },
  });

  return NextResponse.json({ scanId, status: "CANCELLED" });
}
