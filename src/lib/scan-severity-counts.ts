import { prisma } from "@/lib/prisma";

/**
 * Recompute a scan's severity totals from its findings, leaving out findings
 * marked false positive. The totals drive the scan cards, dashboards and
 * trends, so they must be refreshed whenever a finding's status changes; a
 * false positive that still counts as "1 Critical" is how a triaged scan keeps
 * looking as bad as an untriaged one.
 */
export async function recountScanSeverities(scanId: string): Promise<void> {
  const rows = await prisma.finding.groupBy({
    by: ["severity"],
    where: { scanId, status: { not: "FALSE_POSITIVE" } },
    _count: { _all: true },
  });
  const count = (s: string) => rows.find((r) => r.severity === s)?._count._all ?? 0;
  await prisma.scan.update({
    where: { id: scanId },
    data: {
      criticalCount: count("CRITICAL"),
      highCount: count("HIGH"),
      mediumCount: count("MEDIUM"),
      lowCount: count("LOW"),
      infoCount: count("INFO"),
    },
  });
}
