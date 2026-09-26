import { prisma } from "@/lib/prisma";
import type { RemediationRunSnapshot } from "./types";

/** Load a run scoped to the caller's organization (null when not visible). */
export async function loadRunSnapshot(
  runId: string,
  organizationId: string,
): Promise<RemediationRunSnapshot | null> {
  const run = await prisma.remediationRun.findFirst({
    where: { id: runId, organizationId },
    include: {
      items: {
        orderBy: { position: "asc" },
        select: {
          id: true,
          findingId: true,
          position: true,
          status: true,
          title: true,
          severity: true,
          filePath: true,
        },
      },
    },
  });
  if (!run) return null;
  return {
    id: run.id,
    scanId: run.scanId,
    status: run.status,
    provider: run.provider,
    repoUrl: run.repoUrl,
    baseBranch: run.baseBranch,
    headBranch: run.headBranch,
    prUrl: run.prUrl,
    prNumber: run.prNumber,
    errorMessage: run.errorMessage,
    fixedCount: run.fixedCount,
    failedCount: run.failedCount,
    cancelRequested: run.cancelRequested,
    createdAt: run.createdAt.toISOString(),
    startedAt: run.startedAt?.toISOString() ?? null,
    completedAt: run.completedAt?.toISOString() ?? null,
    items: run.items,
  };
}
