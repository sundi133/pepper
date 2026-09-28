/**
 * What changed in a scan compared with the repository's previous state.
 *
 * A project keeps only one Scan row — a rescan deletes the previous scan and
 * its findings before the new scan exists — so "the previous scan" can no
 * longer be read from Finding. The baseline is instead the latest
 * ScanSnapshot of the same repository whose findings were captured.
 *
 * Classification uses the same matching as the Trends comparison
 * (lib/scan-compare), so the scan page, build gate, reports and Trends agree.
 */
import { prisma } from "@/lib/prisma";
import { findingFingerprint } from "@/lib/fix-verification";
import { compareFindingSets, type CompareFinding, type CompareResult } from "@/lib/scan-compare";

export interface BaselineCandidate {
  id: string;
  scanId: string;
  scanType: string;
  completedAt: Date;
}

/**
 * Choose the baseline for a scan: the most recent captured snapshot that
 * finished before the scan started, preferring a full scan (it describes the
 * whole repository) and otherwise one of the same scan type.
 */
export function pickBaseline<T extends BaselineCandidate>(
  candidates: T[],
  current: { scanId: string; scanType: string; createdAt: Date },
): T | null {
  const earlier = candidates
    .filter((c) => c.scanId !== current.scanId && c.completedAt < current.createdAt)
    .sort((a, b) => b.completedAt.getTime() - a.completedAt.getTime());
  return (
    earlier.find((c) => c.scanType === "FULL") ??
    earlier.find((c) => c.scanType === current.scanType) ??
    null
  );
}

/**
 * "Resolved since the baseline" is only meaningful when both scans looked at
 * the whole repository — an incremental or single-scanner scan cannot tell
 * whether findings outside its scope were fixed.
 */
export function canCountResolved(currentScanType: string, baselineScanType: string): boolean {
  return currentScanType === "FULL" && baselineScanType === "FULL";
}

export interface ScanDelta {
  baseline: BaselineCandidate;
  result: CompareResult;
  /** Current findings with no match in the baseline (suppressed ones excluded). */
  newFindingIds: string[];
  /** Current findings that were already present in the baseline. */
  persistingFindingIds: string[];
  /** Baseline findings (open at the time) no longer detected; 0 when not comparable. */
  resolvedCount: number;
}

/** Compare a scan's findings with its baseline. Null when there is no baseline. */
export async function computeScanDelta(scanId: string): Promise<ScanDelta | null> {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: { id: true, projectId: true, scanType: true, createdAt: true },
  });
  if (!scan) return null;

  const candidates = await prisma.scanSnapshot.findMany({
    where: {
      projectId: scan.projectId,
      findingsCaptured: true,
      scanId: { not: scan.id },
      completedAt: { lt: scan.createdAt },
    },
    orderBy: { completedAt: "desc" },
    take: 25,
    select: { id: true, scanId: true, scanType: true, completedAt: true },
  });
  const baseline = pickBaseline(candidates, {
    scanId: scan.id,
    scanType: scan.scanType,
    createdAt: scan.createdAt,
  });
  if (!baseline) return null;

  const [baseFindings, currentRows] = await Promise.all([
    prisma.scanSnapshotFinding.findMany({
      where: { snapshotId: baseline.id },
      select: {
        fingerprint: true,
        findingId: true,
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
    }),
    prisma.finding.findMany({
      where: { scanId: scan.id },
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
    }),
  ]);
  const current: CompareFinding[] = currentRows.map(({ id, ...f }) => ({
    ...f,
    findingId: id,
    fingerprint: findingFingerprint(f),
  }));

  const result = compareFindingSets(baseFindings, current);
  return {
    baseline,
    result,
    newFindingIds: result.introduced.map((f) => f.findingId).filter((id): id is string => !!id),
    persistingFindingIds: result.persisting
      .map((p) => p.target.findingId)
      .filter((id): id is string => !!id),
    resolvedCount: canCountResolved(scan.scanType, baseline.scanType) ? result.fixed.length : 0,
  };
}
