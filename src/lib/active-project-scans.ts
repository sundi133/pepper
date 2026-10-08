import { prisma } from "@/lib/prisma";
import { scanQueue } from "@/lib/queue";

const ACTIVE = ["QUEUED", "RUNNING", "PAUSED"] as const;

/**
 * A repository keeps every scan as history; starting a new one stops any scan
 * of it still in progress, so two runs never race on the same repository. The
 * stopped scan is marked CANCELLED (the worker sees that and stops) and its
 * queued job removed; it stays in the history with what it found so far.
 * Returns the ids of the scans cancelled.
 */
export async function cancelActiveScansForProject(projectId: string): Promise<string[]> {
  const active = await prisma.scan.findMany({
    where: { projectId, status: { in: [...ACTIVE] } },
    select: { id: true, jobId: true },
  });
  if (active.length === 0) return [];

  for (const s of active) {
    if (!s.jobId) continue;
    try {
      const job = await scanQueue.getJob(s.jobId);
      if (job) await job.remove();
    } catch {
      // Already processing (the status change below stops it) or already gone.
    }
  }

  await prisma.scan.updateMany({
    where: { id: { in: active.map((s) => s.id) }, status: { in: [...ACTIVE] } },
    data: { status: "CANCELLED", completedAt: new Date() },
  });
  return active.map((s) => s.id);
}
