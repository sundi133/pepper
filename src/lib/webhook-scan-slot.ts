import { prisma } from "@/lib/prisma";
import { cancelActiveScansForProject, cancelActiveScansInScope } from "@/lib/active-project-scans";
import type { ScanJobData } from "@/lib/queue";

/**
 * Before a webhook starts a scan: a push of the same commit that is already
 * queued or running is not scanned twice, and the scan it replaces is stopped.
 * Earlier scans stay as history.
 *
 * With `prNumber` (a PR scan) or `branch` (a push), only that PR's or that
 * branch's scan is replaced, so concurrent pull requests don't cancel each
 * other. Without either, any scan of the repository in progress is stopped.
 */
export async function ensureWebhookScanSlot(params: {
  projectId: string;
  commitSha?: string;
  scanType: ScanJobData["scanType"];
  prNumber?: number;
  branch?: string;
}): Promise<{ scanId: string; status: "ALREADY_QUEUED" } | { status: "READY" }> {
  const commitSha = params.commitSha?.trim();
  const scope =
    params.prNumber != null
      ? { prNumber: params.prNumber }
      : params.branch?.trim()
        ? { branch: params.branch.trim() }
        : null;
  const existing = await prisma.scan.findFirst({
    where: {
      projectId: params.projectId,
      ...(scope ? ("prNumber" in scope ? { prNumber: scope.prNumber } : { prNumber: null, branch: scope.branch }) : {}),
    },
    orderBy: { createdAt: "desc" },
    select: { id: true, commitSha: true, scanType: true, status: true },
  });

  if (!existing) {
    return { status: "READY" };
  }

  if (
    commitSha &&
    existing.commitSha === commitSha &&
    existing.scanType === params.scanType &&
    (existing.status === "QUEUED" || existing.status === "RUNNING")
  ) {
    return { scanId: existing.id, status: "ALREADY_QUEUED" };
  }

  if (scope) await cancelActiveScansInScope(params.projectId, scope);
  else await cancelActiveScansForProject(params.projectId);
  return { status: "READY" };
}
