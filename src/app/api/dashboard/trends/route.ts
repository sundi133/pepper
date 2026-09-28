import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import {
  buildOrgSeries,
  buildRepoSeries,
  fixImpacts,
  repoComparison,
  seriesComparison,
  type HistoryPoint,
} from "@/lib/scan-history";

/**
 * Severity trends.
 *
 * Without `project`: org-wide — each day sums every repository's latest
 * known state (carried forward between scans), plus how many repositories
 * were scanned / failed the build gate that day.
 *
 * With `project=<id>`: one repository — each day carries forward the latest
 * full scan, plus AI remediation runs with the repository state before and
 * after each fix, and a before/after headline comparison.
 *
 * History comes from ScanSnapshot (a project keeps only its latest Scan row),
 * merged with current completed scans that have no snapshot yet.
 */
export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const url = new URL(req.url);
  const daysRaw = parseInt(url.searchParams.get("days") || "30", 10);
  const days = Math.max(7, Math.min(daysRaw || 30, 365));
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const projectParam = url.searchParams.get("project")?.trim() || null;

  const projects = await prisma.project.findMany({
    where: { organizationId: orgId },
    select: { id: true, name: true, repoUrl: true },
    orderBy: { name: "asc" },
  });
  const project = projectParam ? projects.find((p) => p.id === projectParam) : null;
  if (projectParam && !project) {
    return NextResponse.json({ error: "Repository not found" }, { status: 404 });
  }
  const projectFilter = project ? { projectId: project.id } : {};

  // Carry-forward needs each repository's state at the start of the window:
  // everything inside the window plus the last snapshot before it, per repo.
  const orgWhere = { organizationId: orgId, ...projectFilter };
  const [inWindow, beforeWindow, liveScans] = await Promise.all([
    prisma.scanSnapshot.findMany({
      where: { ...orgWhere, completedAt: { gte: since } },
      orderBy: { completedAt: "asc" },
    }),
    prisma.scanSnapshot.findMany({
      where: { ...orgWhere, completedAt: { lt: since }, scanType: "FULL" },
      orderBy: [{ projectId: "asc" }, { completedAt: "desc" }],
      distinct: ["projectId"],
    }),
    // One row per project (rescans replace it) — covers scans that finished
    // before snapshots existed or whose snapshot write failed.
    prisma.scan.findMany({
      where: {
        project: { organizationId: orgId },
        status: "COMPLETED",
        completedAt: { not: null },
        ...projectFilter,
      },
      select: {
        id: true,
        projectId: true,
        scanType: true,
        commitSha: true,
        completedAt: true,
        criticalCount: true,
        highCount: true,
        mediumCount: true,
        lowCount: true,
        infoCount: true,
        gateResult: true,
      },
    }),
  ]);
  const snapshots = [...beforeWindow, ...inWindow];

  const points: Array<HistoryPoint & { projectId: string }> = snapshots.map((s) => ({
    scanId: s.scanId,
    projectId: s.projectId,
    scanType: s.scanType,
    completedAt: s.completedAt,
    commitSha: s.commitSha,
    gateResult: s.gateResult,
    critical: s.criticalCount,
    high: s.highCount,
    medium: s.mediumCount,
    low: s.lowCount,
    info: s.infoCount,
  }));
  const seen = new Set(points.map((p) => p.scanId));
  for (const s of liveScans) {
    if (!s.completedAt || seen.has(s.id)) continue;
    points.push({
      scanId: s.id,
      projectId: s.projectId,
      scanType: s.scanType,
      completedAt: s.completedAt,
      commitSha: s.commitSha,
      gateResult: s.gateResult,
      critical: s.criticalCount,
      high: s.highCount,
      medium: s.mediumCount,
      low: s.lowCount,
      info: s.infoCount,
    });
  }

  let series;
  let comparison;
  let repo: Record<string, unknown> | null = null;

  if (project) {
    series = buildRepoSeries(points, days);
    const runs = await prisma.remediationRun.findMany({
      where: {
        organizationId: orgId,
        projectId: project.id,
        createdAt: { gte: since },
        status: { in: ["COMPLETED", "PARTIAL", "FAILED"] },
      },
      select: {
        id: true,
        status: true,
        createdAt: true,
        completedAt: true,
        prUrl: true,
        prNumber: true,
        fixedCount: true,
        failedCount: true,
      },
      orderBy: { createdAt: "asc" },
    });
    const impacts = fixImpacts(runs, points);
    comparison = repoComparison(points, impacts, since);
    repo = {
      project,
      remediations: impacts,
      scans: points
        .filter((p) => p.completedAt >= since)
        .sort((a, b) => b.completedAt.getTime() - a.completedAt.getTime())
        .slice(0, 50)
        .map((p) => ({
          scanId: p.scanId,
          scanType: p.scanType,
          completedAt: p.completedAt.toISOString(),
          commitSha: p.commitSha,
          gateResult: p.gateResult,
          critical: p.critical,
          high: p.high,
          medium: p.medium,
          low: p.low,
          info: p.info,
        })),
    };
  } else {
    series = buildOrgSeries(points, days);
    comparison = { ...seriesComparison(series), baselineLabel: "window_start" as const };
  }

  // Mean-time-to-resolve over the same window
  const resolved = await prisma.finding.findMany({
    where: {
      scan: { project: { organizationId: orgId }, ...projectFilter },
      status: "RESOLVED",
      statusUpdatedAt: { gte: since },
    },
    select: {
      createdAt: true,
      statusUpdatedAt: true,
      severity: true,
    },
  });
  const mttrBySeverity: Record<string, { count: number; totalMs: number }> = {};
  for (const f of resolved) {
    if (!f.statusUpdatedAt) continue;
    const ms = f.statusUpdatedAt.getTime() - f.createdAt.getTime();
    const sev = f.severity;
    if (!mttrBySeverity[sev]) mttrBySeverity[sev] = { count: 0, totalMs: 0 };
    mttrBySeverity[sev].count++;
    mttrBySeverity[sev].totalMs += ms;
  }
  const mttr = Object.fromEntries(
    Object.entries(mttrBySeverity).map(([sev, v]) => [
      sev,
      {
        count: v.count,
        meanHours: v.count > 0 ? v.totalMs / v.count / (1000 * 60 * 60) : 0,
      },
    ]),
  );

  return NextResponse.json({
    days,
    series,
    mttr,
    projects: projects.map((p) => ({ id: p.id, name: p.name })),
    comparison,
    repo,
  });
}
