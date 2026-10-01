import { prisma } from "@/lib/prisma";

/**
 * Clear what an earlier, interrupted attempt of this scan saved.
 *
 * A scan job can start more than once: the queue re-runs it when the worker
 * that held it is restarted or crashes. Every start is a full run, and
 * findings are saved (and severity totals incremented) as scanners finish, so
 * without this the re-run duplicates every finding and doubles the totals the
 * build gate reads. Same reset the resume route does before re-queueing.
 *
 * Returns how many findings were removed (0 on a normal first start).
 */
export async function clearPreviousAttempt(scanId: string): Promise<number> {
  const [removed] = await prisma.$transaction([
    prisma.finding.deleteMany({ where: { scanId } }),
    prisma.scanArtifact.deleteMany({ where: { scanId } }),
    prisma.scan.update({
      where: { id: scanId },
      data: {
        completedAt: null,
        errorMessage: null,
        gateResult: "PENDING",
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        filesScanned: 0,
        depsScanned: 0,
        autoResolvedCount: 0,
        newFindingCount: 0,
      },
    }),
  ]);
  return removed.count;
}
