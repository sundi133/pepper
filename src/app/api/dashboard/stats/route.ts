import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  // 1. Trend data — severity counts per completed scan (last 30 scans)
  const recentScans = await prisma.scan.findMany({
    where: {
      status: "COMPLETED",
      project: { organizationId: orgId },
    },
    orderBy: { completedAt: "asc" },
    take: 30,
    select: {
      id: true,
      completedAt: true,
      criticalCount: true,
      highCount: true,
      mediumCount: true,
      lowCount: true,
      project: { select: { name: true } },
    },
  });

  const trend = recentScans.map((s) => ({
    date: s.completedAt?.toISOString().split("T")[0] || "",
    label: s.project.name,
    critical: s.criticalCount,
    high: s.highCount,
    medium: s.mediumCount,
    low: s.lowCount,
  }));

  // 2. Severity breakdown — aggregate across all findings in org
  const severityBreakdown = await prisma.finding.groupBy({
    by: ["severity"],
    _count: true,
    where: {
      scan: { project: { organizationId: orgId } },
    },
  });

  const severity = severityBreakdown.map((s) => ({
    name: s.severity,
    count: s._count,
  }));

  // 3. Scanner distribution
  const scannerBreakdown = await prisma.finding.groupBy({
    by: ["scanner"],
    _count: true,
    where: {
      scan: { project: { organizationId: orgId } },
    },
  });

  const scanners = scannerBreakdown.map((s) => ({
    name: s.scanner,
    count: s._count,
  }));

  // 4. Top vulnerable files (top 10)
  const topFiles = await prisma.finding.groupBy({
    by: ["filePath"],
    _count: true,
    where: {
      scan: { project: { organizationId: orgId } },
      filePath: { not: null },
    },
    orderBy: { _count: { filePath: "desc" } },
    take: 10,
  });

  const files = topFiles.map((f) => ({
    filePath: f.filePath || "unknown",
    count: f._count,
  }));

  // 5. Finding status breakdown
  const statusBreakdown = await prisma.finding.groupBy({
    by: ["status"],
    _count: true,
    where: {
      scan: { project: { organizationId: orgId } },
    },
  });

  const statuses = statusBreakdown.map((s) => ({
    name: s.status,
    count: s._count,
  }));

  return NextResponse.json({
    trend,
    severity,
    scanners,
    topFiles: files,
    statuses,
  });
}
