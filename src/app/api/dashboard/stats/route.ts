import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { latestCompletedScanIds } from "@/lib/latest-scans";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  // Totals come from each repository's latest completed scan: earlier scans
  // are kept as history and would otherwise count the same issues again.
  const currentScan = { scanId: { in: await latestCompletedScanIds(orgId) } };

  const startOfMonth = new Date();
  startOfMonth.setDate(1);
  startOfMonth.setHours(0, 0, 0, 0);

  const [
    severityBreakdown,
    projectCount,
    memberCount,
    monitoredSchedules,
    secretsFindingCount,
    dependencyFindingCount,
    resolvedThisMonth,
    lastScan,
    recentProjects,
    recentScansForFeed,
  ] = await Promise.all([
    prisma.finding.groupBy({
      by: ["severity"],
      _count: true,
      where: currentScan,
    }),
    prisma.project.count({ where: { organizationId: orgId } }),
    prisma.orgMember.count({ where: { organizationId: orgId } }),
    prisma.scanSchedule.count({
      where: { enabled: true, project: { organizationId: orgId } },
    }),
    prisma.finding.count({
      where: {
        ...currentScan,
        scanner: { in: ["SECRETS_PATTERN", "SECRETS_LLM"] },
      },
    }),
    prisma.finding.count({
      where: {
        ...currentScan,
        scanner: { in: ["SCA", "MALICIOUS_PKG"] },
      },
    }),
    prisma.finding.count({
      where: {
        ...currentScan,
        status: "RESOLVED",
        statusUpdatedAt: { gte: startOfMonth },
      },
    }),
    prisma.scan.findFirst({
      where: { project: { organizationId: orgId } },
      orderBy: [{ completedAt: "desc" }, { createdAt: "desc" }],
      select: {
        id: true,
        status: true,
        scanType: true,
        completedAt: true,
        createdAt: true,
      },
    }),
    prisma.project.findMany({
      where: { organizationId: orgId },
      orderBy: { updatedAt: "desc" },
      take: 6,
      select: {
        id: true,
        name: true,
        updatedAt: true,
        scans: {
          where: { status: "COMPLETED" },
          orderBy: { completedAt: "desc" },
          take: 1,
          select: {
            id: true,
            criticalCount: true,
            highCount: true,
            mediumCount: true,
            lowCount: true,
            infoCount: true,
            completedAt: true,
          },
        },
      },
    }),
    prisma.scan.findMany({
      where: { project: { organizationId: orgId } },
      orderBy: { createdAt: "desc" },
      take: 12,
      select: {
        id: true,
        status: true,
        scanType: true,
        createdAt: true,
        project: { select: { name: true } },
      },
    }),
  ]);

  const severity = severityBreakdown.map((s) => ({
    name: s.severity,
    count: s._count,
  }));

  const overview = {
    projectCount,
    memberCount,
    monitoredSchedules,
    secretsFindingCount,
    dependencyFindingCount,
    resolvedThisMonth,
    lastScanAt: lastScan?.completedAt ?? lastScan?.createdAt ?? null,
    lastScanStatus: lastScan?.status ?? null,
    recentProjects: recentProjects.map((p) => {
      const s = p.scans[0];
      return {
        id: p.id,
        name: p.name,
        updatedAt: p.updatedAt.toISOString(),
        lastScanAt: s?.completedAt?.toISOString() ?? null,
        criticalCount: s?.criticalCount ?? 0,
        highCount: s?.highCount ?? 0,
        mediumCount: s?.mediumCount ?? 0,
        lowCount: s?.lowCount ?? 0,
        infoCount: s?.infoCount ?? 0,
      };
    }),
    activities: recentScansForFeed.map((s) => ({
      id: s.id,
      status: s.status,
      scanType: s.scanType,
      createdAt: s.createdAt.toISOString(),
      projectName: s.project.name,
    })),
  };

  return NextResponse.json({ severity, overview });
}
