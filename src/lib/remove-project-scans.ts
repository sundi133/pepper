import { prisma } from "@/lib/prisma";
import { scanQueue } from "@/lib/queue";
import { deleteObject } from "@/lib/minio";

/**
 * Deletes every scan for a project (findings & artifacts cascade),
 * removes queued Bull jobs, and best-effort deletes MinIO objects.
 * Used so each project keeps at most one active scan record.
 */
export async function removeAllScansForProject(projectId: string): Promise<void> {
  const scans = await prisma.scan.findMany({
    where: { projectId },
    select: {
      id: true,
      jobId: true,
      sourceRef: true,
      sourceType: true,
      artifacts: { select: { objectKey: true } },
    },
  });

  if (scans.length === 0) return;

  const objectKeys = new Set<string>();
  for (const s of scans) {
    for (const a of s.artifacts) {
      if (a.objectKey) objectKeys.add(a.objectKey);
    }
    if (
      s.sourceType === "UPLOAD" &&
      s.sourceRef &&
      s.sourceRef.startsWith("scans/")
    ) {
      objectKeys.add(s.sourceRef);
    }
  }

  for (const s of scans) {
    if (s.jobId) {
      try {
        const job = await scanQueue.getJob(s.jobId);
        await job?.remove();
      } catch {
        // job may be active or already removed
      }
    }
  }

  await prisma.scan.deleteMany({ where: { projectId } });

  await Promise.allSettled(
    [...objectKeys].map(async (key) => {
      try {
        await deleteObject(key);
      } catch {
        // object may not exist
      }
    }),
  );
}
