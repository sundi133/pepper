import { prisma } from "@/lib/prisma";
import { removeAllScansForProject } from "@/lib/remove-project-scans";
import type { ScanJobData } from "@/lib/queue";

/**
 * Pepper keeps one Scan row per project (`projectId` is unique).
 * Webhooks must replace an existing scan before creating a new one.
 */
export async function ensureWebhookScanSlot(params: {
  projectId: string;
  commitSha?: string;
  scanType: ScanJobData["scanType"];
}): Promise<{ scanId: string; status: "ALREADY_QUEUED" } | { status: "READY" }> {
  const commitSha = params.commitSha?.trim();
  const existing = await prisma.scan.findUnique({
    where: { projectId: params.projectId },
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

  await removeAllScansForProject(params.projectId);
  return { status: "READY" };
}
