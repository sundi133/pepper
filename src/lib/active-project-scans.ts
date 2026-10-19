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

/**
 * Like cancelActiveScansForProject, but only the scans matching `scope`: one
 * pull request's, or one branch's outside any pull request. Webhook scans use
 * it so a review of one PR never stops another PR's (docs/PR_REVIEW_BOT_SPEC.md §3).
 */
export async function cancelActiveScansInScope(
  projectId: string,
  scope: { prNumber: number } | { branch: string },
): Promise<string[]> {
  const where =
    "prNumber" in scope
      ? { projectId, prNumber: scope.prNumber, status: { in: [...ACTIVE] } }
      : { projectId, prNumber: null, branch: scope.branch, status: { in: [...ACTIVE] } };
  const active = await prisma.scan.findMany({ where, select: { id: true, jobId: true } });
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
