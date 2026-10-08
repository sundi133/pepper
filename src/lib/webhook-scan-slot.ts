import { prisma } from "@/lib/prisma";
import { cancelActiveScansForProject } from "@/lib/active-project-scans";
import type { ScanJobData } from "@/lib/queue";

/**
 * Before a webhook starts a scan: a push of the same commit that is already
 * queued or running is not scanned twice, and any other scan of the
 * repository still in progress is stopped. Earlier scans stay as history.
 */
export async function ensureWebhookScanSlot(params: {
  projectId: string;
  commitSha?: string;
  scanType: ScanJobData["scanType"];
}): Promise<{ scanId: string; status: "ALREADY_QUEUED" } | { status: "READY" }> {
  const commitSha = params.commitSha?.trim();
  const existing = await prisma.scan.findFirst({
    where: { projectId: params.projectId },
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

  await cancelActiveScansForProject(params.projectId);
  return { status: "READY" };
}
