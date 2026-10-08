/**
 * Repository scan history for trends. Each completed scan's totals are copied
 * into ScanSnapshot, which outlives the scan itself; the pure
 * helpers below turn those snapshots into daily series and before/after-fix
 * comparisons.
 */
import { prisma } from "@/lib/prisma";

export interface SeverityTotals {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface HistoryPoint extends SeverityTotals {
  scanId: string;
  scanType: string;
  completedAt: Date;
  commitSha: string | null;
  gateResult: string;
}

export interface DayPoint extends SeverityTotals {
  date: string;
  scans: number;
  gateFailed: number;
}

/** Copy a completed scan's totals into history. Safe to call repeatedly. */
export async function recordScanSnapshot(scanId: string): Promise<void> {
  const s = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      id: true,
      status: true,
      projectId: true,
      scanType: true,
      branch: true,
      commitSha: true,
      completedAt: true,
      criticalCount: true,
      highCount: true,
      mediumCount: true,
      lowCount: true,
      infoCount: true,
      filesScanned: true,
      gateResult: true,
      project: { select: { organizationId: true } },
    },
  });
  if (!s || s.status !== "COMPLETED" || !s.completedAt) return;
  const totals = {
    criticalCount: s.criticalCount,
    highCount: s.highCount,
    mediumCount: s.mediumCount,
    lowCount: s.lowCount,
    infoCount: s.infoCount,
    filesScanned: s.filesScanned,
    gateResult: s.gateResult,
  };
  const snapshot = await prisma.scanSnapshot.upsert({
    where: { scanId: s.id },
    create: {
      organizationId: s.project.organizationId,
      projectId: s.projectId,
      scanId: s.id,
      scanType: s.scanType,
      branch: s.branch,
      commitSha: s.commitSha,
      completedAt: s.completedAt,
      ...totals,
    },
    update: totals,
    select: { id: true },
  });
  await captureSnapshotFindings(snapshot.id, s.id);
}

const CAPTURE_CHUNK = 1000;

/**
 * Copy a scan's findings into the snapshot (replacing any earlier copy), so
 * this version stays comparable after a rescan deletes the scan's findings.
 */
export async function captureSnapshotFindings(snapshotId: string, scanId: string): Promise<number> {
  const { findingFingerprint } = await import("@/lib/fix-verification");
  const findings = await prisma.finding.findMany({
    where: { scanId },
    select: {
      id: true,
      scanner: true,
      severity: true,
      status: true,
      title: true,
      filePath: true,
      startLine: true,
      ruleId: true,
      cweId: true,
      cveId: true,
    },
  });
  const rows = findings.map((f) => ({
    snapshotId,
    fingerprint: findingFingerprint(f),
    findingId: f.id,
    scanner: f.scanner,
    severity: f.severity,
    status: f.status,
    title: f.title.slice(0, 500),
    filePath: f.filePath,
    startLine: f.startLine,
    ruleId: f.ruleId,
    cweId: f.cweId,
    cveId: f.cveId,
  }));
  await prisma.$transaction(async (tx) => {
    await tx.scanSnapshotFinding.deleteMany({ where: { snapshotId } });
    for (let i = 0; i < rows.length; i += CAPTURE_CHUNK) {
      await tx.scanSnapshotFinding.createMany({ data: rows.slice(i, i + CAPTURE_CHUNK) });
    }
    await tx.scanSnapshot.update({ where: { id: snapshotId }, data: { findingsCaptured: true } });
  }, { timeout: 60_000 });
  return rows.length;
}

export function dayKey(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function totalOf(t: SeverityTotals): number {
  return t.critical + t.high + t.medium + t.low + t.info;
}

/**
 * Incremental (PR diff) scans only cover changed files, so their totals are
 * not the repository's state; *_ONLY scans cover one scanner. Only full scans
 * describe the whole repository.
 */
export function isWholeRepoScan(scanType: string): boolean {
  return scanType === "FULL";
}

/**
 * Points that describe the repository's state, oldest first: full scans, or —
 * for a repo that only ever ran targeted scans — every non-incremental scan.
 */
export function repoStatePoints(points: HistoryPoint[]): HistoryPoint[] {
  const full = points.filter((p) => isWholeRepoScan(p.scanType));
  const chosen = full.length ? full : points.filter((p) => p.scanType !== "INCREMENTAL");
  return chosen.slice().sort((a, b) => a.completedAt.getTime() - b.completedAt.getTime());
}

/**
 * Daily series for ONE repository: each day shows the latest full scan up to
 * and including that day (state carries forward between scans). Days before
 * the first known scan are null so charts render a gap instead of a false 0.
 */
export function buildRepoSeries(
  points: HistoryPoint[],
  days: number,
  now = new Date(),
): Array<DayPoint | (Omit<DayPoint, keyof SeverityTotals> & { [K in keyof SeverityTotals]: null })> {
  const sorted = repoStatePoints(points);
  const out = [];
  let idx = 0;
  let current: HistoryPoint | null = null;
  for (let i = days - 1; i >= 0; i--) {
    const day = new Date(now.getTime() - i * 86_400_000);
    const key = dayKey(day);
    let scans = 0;
    let gateFailed = 0;
    while (idx < sorted.length && dayKey(sorted[idx].completedAt) <= key) {
      current = sorted[idx];
      if (dayKey(sorted[idx].completedAt) === key) {
        scans++;
        if (sorted[idx].gateResult === "FAILED") gateFailed++;
      }
      idx++;
    }
    out.push(
      current
        ? {
            date: key,
            critical: current.critical,
            high: current.high,
            medium: current.medium,
            low: current.low,
            info: current.info,
            scans,
            gateFailed,
          }
        : { date: key, critical: null, high: null, medium: null, low: null, info: null, scans, gateFailed },
    );
  }
  return out;
}

export interface RemediationRef {
  id: string;
  status: string;
  createdAt: Date;
  completedAt: Date | null;
  prUrl: string | null;
  prNumber: number | null;
  fixedCount: number;
  failedCount: number;
}

export interface FixImpact {
  runId: string;
  status: string;
  openedAt: string;
  prUrl: string | null;
  prNumber: number | null;
  fixed: number;
  failed: number;
  /** Last full scan before the run started. */
  before: (SeverityTotals & { at: string }) | null;
  /** First full scan after the run finished (i.e. after the fix could land). */
  after: (SeverityTotals & { at: string }) | null;
}

function totalsAt(p: HistoryPoint): SeverityTotals & { at: string } {
  return {
    critical: p.critical,
    high: p.high,
    medium: p.medium,
    low: p.low,
    info: p.info,
    at: p.completedAt.toISOString(),
  };
}

/** Pair each remediation run with the repository state before and after it. */
export function fixImpacts(runs: RemediationRef[], points: HistoryPoint[]): FixImpact[] {
  const full = repoStatePoints(points);
  return runs
    .slice()
    .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
    .map((r) => {
      const started = r.createdAt.getTime();
      const finished = (r.completedAt ?? r.createdAt).getTime();
      const before = [...full].reverse().find((p) => p.completedAt.getTime() <= started) ?? null;
      const after = full.find((p) => p.completedAt.getTime() > finished) ?? null;
      return {
        runId: r.id,
        status: r.status,
        openedAt: (r.completedAt ?? r.createdAt).toISOString(),
        prUrl: r.prUrl,
        prNumber: r.prNumber,
        fixed: r.fixedCount,
        failed: r.failedCount,
        before: before ? totalsAt(before) : null,
        after: after ? totalsAt(after) : null,
      };
    });
}

/**
 * Headline comparison for a repository over the window: the state before the
 * first AI fix (or the first scan in the window when there were no fixes)
 * versus the latest scan.
 */
export function repoComparison(
  points: HistoryPoint[],
  impacts: FixImpact[],
  since: Date,
): {
  baseline: (SeverityTotals & { at: string }) | null;
  current: (SeverityTotals & { at: string }) | null;
  baselineLabel: "before_first_fix" | "window_start";
} {
  const full = repoStatePoints(points);
  const current = full.length ? totalsAt(full[full.length - 1]) : null;
  const firstFix = impacts.find((i) => i.prUrl && i.before);
  if (firstFix?.before) {
    return { baseline: firstFix.before, current, baselineLabel: "before_first_fix" };
  }
  const startPoint =
    [...full].reverse().find((p) => p.completedAt < since) ??
    full.find((p) => p.completedAt >= since) ??
    null;
  return {
    baseline: startPoint ? totalsAt(startPoint) : null,
    current,
    baselineLabel: "window_start",
  };
}

/**
 * Org-wide daily series: each day is the SUM of every repository's latest
 * known state (carried forward), so a repository that was not scanned that
 * day still counts. `scans` / `gateFailed` count repositories scanned that
 * day (latest scan per repository per day).
 */
export function buildOrgSeries(
  points: Array<HistoryPoint & { projectId: string }>,
  days: number,
  now = new Date(),
): ReturnType<typeof buildRepoSeries> {
  const byProject = new Map<string, HistoryPoint[]>();
  for (const p of points) {
    byProject.set(p.projectId, [...(byProject.get(p.projectId) ?? []), p]);
  }
  const perRepo = [...byProject.values()].map((pts) => buildRepoSeries(pts, days, now));

  const latestPerDayProject = new Map<string, HistoryPoint & { projectId: string }>();
  for (const p of points) {
    const key = `${dayKey(p.completedAt)}|${p.projectId}`;
    const existing = latestPerDayProject.get(key);
    if (!existing || existing.completedAt < p.completedAt) latestPerDayProject.set(key, p);
  }
  const activity = new Map<string, { scans: number; gateFailed: number }>();
  for (const p of latestPerDayProject.values()) {
    const a = activity.get(dayKey(p.completedAt)) ?? { scans: 0, gateFailed: 0 };
    a.scans++;
    if (p.gateResult === "FAILED") a.gateFailed++;
    activity.set(dayKey(p.completedAt), a);
  }

  const out: ReturnType<typeof buildRepoSeries> = [];
  for (let i = days - 1; i >= 0; i--) {
    const key = dayKey(new Date(now.getTime() - i * 86_400_000));
    const idx = days - 1 - i;
    const known = perRepo.map((s) => s[idx]).filter((d) => d.critical !== null) as DayPoint[];
    const act = activity.get(key) ?? { scans: 0, gateFailed: 0 };
    out.push(
      known.length
        ? {
            date: key,
            critical: known.reduce((n, d) => n + d.critical, 0),
            high: known.reduce((n, d) => n + d.high, 0),
            medium: known.reduce((n, d) => n + d.medium, 0),
            low: known.reduce((n, d) => n + d.low, 0),
            info: known.reduce((n, d) => n + d.info, 0),
            ...act,
          }
        : { date: key, critical: null, high: null, medium: null, low: null, info: null, ...act },
    );
  }
  return out;
}

/** First vs last known day of a series, for the headline comparison. */
export function seriesComparison(
  series: ReturnType<typeof buildRepoSeries>,
): {
  baseline: (SeverityTotals & { at: string }) | null;
  current: (SeverityTotals & { at: string }) | null;
} {
  const known = series.filter((d) => d.critical !== null) as DayPoint[];
  const pick = (d: DayPoint | undefined) =>
    d ? { critical: d.critical, high: d.high, medium: d.medium, low: d.low, info: d.info, at: d.date } : null;
  return { baseline: pick(known[0]), current: pick(known[known.length - 1]) };
}
