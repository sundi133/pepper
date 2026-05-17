import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";

/**
 * Historical severity trend across all scans in the org.
 * Buckets by day (default 30 days). Aggregates the latest scan per project
 * within each day so projects with frequent scans don't dominate trends.
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

  const scans = await prisma.scan.findMany({
    where: {
      project: { organizationId: orgId },
      completedAt: { gte: since },
      status: "COMPLETED",
    },
    select: {
      id: true,
      projectId: true,
      completedAt: true,
      criticalCount: true,
      highCount: true,
      mediumCount: true,
      lowCount: true,
      infoCount: true,
      gateResult: true,
    },
    orderBy: { completedAt: "asc" },
  });

  const buckets = new Map<
    string,
    {
      date: string;
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
      scans: number;
      gateFailed: number;
    }
  >();

  function bucketKey(d: Date): string {
    return d.toISOString().slice(0, 10);
  }

  // For each (day, project), keep the latest scan
  const latestPerDayProject = new Map<string, (typeof scans)[number]>();
  for (const s of scans) {
    if (!s.completedAt) continue;
    const key = `${bucketKey(s.completedAt)}|${s.projectId}`;
    const existing = latestPerDayProject.get(key);
    if (!existing || (existing.completedAt! < s.completedAt)) {
      latestPerDayProject.set(key, s);
    }
  }

  for (const s of latestPerDayProject.values()) {
    if (!s.completedAt) continue;
    const day = bucketKey(s.completedAt);
    let b = buckets.get(day);
    if (!b) {
      b = {
        date: day,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        scans: 0,
        gateFailed: 0,
      };
      buckets.set(day, b);
    }
    b.critical += s.criticalCount;
    b.high += s.highCount;
    b.medium += s.mediumCount;
    b.low += s.lowCount;
    b.info += s.infoCount;
    b.scans += 1;
    if (s.gateResult === "FAILED") b.gateFailed += 1;
  }

  // Fill missing days for nicer charts
  const series: typeof buckets extends Map<string, infer V> ? V[] : never = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
    const key = bucketKey(d);
    series.push(
      buckets.get(key) || {
        date: key,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        scans: 0,
        gateFailed: 0,
      },
    );
  }

  // Mean-time-to-resolve over the same window
  const resolved = await prisma.finding.findMany({
    where: {
      scan: { project: { organizationId: orgId } },
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
  });
}
