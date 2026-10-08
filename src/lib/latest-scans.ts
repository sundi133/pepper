import { prisma } from "@/lib/prisma";

/**
 * Each repository's latest completed scan in an organization. Repositories
 * keep their scan history, so totals across "all findings" must be taken from
 * these scans only, or every rescan would count the same issues again.
 */
export async function latestCompletedScanIds(organizationId: string): Promise<string[]> {
  const rows = await prisma.scan.findMany({
    where: { project: { organizationId }, status: "COMPLETED" },
    orderBy: [{ projectId: "asc" }, { completedAt: "desc" }],
    distinct: ["projectId"],
    select: { id: true },
  });
  return rows.map((r) => r.id);
}
