import { prisma } from "@/lib/prisma";
import type { Logger } from "pino";

// ─── Fingerprinting ──────────────────────────────────────────────────────────
//
// A finding's "fingerprint" is a stable identifier across scans that allows us
// to detect when the same finding disappears (i.e., was fixed) or was already
// present in a previous scan (i.e., is persisting rather than new).
//
// We bucket startLine to ±4 lines (floor to nearest 5) so minor code reformats
// don't break the match.

type FingerprintInput = {
  scanner: string;
  ruleId: string | null;
  cweId: string | null;
  cveId: string | null;
  filePath: string | null;
  startLine: number | null;
  title: string;
};

function normalizeFindingTitle(title: string): string {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
}

/** What the finding is (rule / CVE / CWE, else its normalized title) — no location. */
export function findingRuleKey(f: Pick<FingerprintInput, "ruleId" | "cveId" | "cweId" | "title">): string {
  return f.ruleId ?? f.cveId ?? f.cweId ?? normalizeFindingTitle(f.title);
}

export function findingFingerprint(f: FingerprintInput): string {
  return [
    f.scanner,
    findingRuleKey(f),
    f.filePath ?? "",
    f.startLine != null ? Math.floor(f.startLine / 5) : 0,
  ].join(":");
}

// ─── Core logic ─────────────────────────────────────────────────────────────

/**
 * Tag each finding of a completed scan as new or persisting, and record how
 * many previously-open findings are no longer detected.
 *
 * The comparison baseline is the repository's latest captured ScanSnapshot
 * (see lib/scan-delta), which outlives the scans it was taken from. With no
 * baseline (first scan, or history recorded before finding capture) findings
 * keep isNew = null and both counts stay 0.
 */
export async function autoResolveFixedFindings(
  scanId: string,
  projectId: string,
  log: Logger,
): Promise<{ resolved: number; newCount: number; persistingCount: number }> {
  const { computeScanDelta } = await import("@/lib/scan-delta");
  const delta = await computeScanDelta(scanId);
  if (!delta) {
    return { resolved: 0, newCount: 0, persistingCount: 0 };
  }

  if (delta.newFindingIds.length > 0) {
    await prisma.finding.updateMany({
      where: { id: { in: delta.newFindingIds }, scanId },
      data: { isNew: true },
    });
  }
  if (delta.persistingFindingIds.length > 0) {
    await prisma.finding.updateMany({
      where: { id: { in: delta.persistingFindingIds }, scanId },
      data: { isNew: false },
    });
  }

  // The earlier scan's findings are left as they were (they are history);
  // the count tells the user what this scan no longer detects.
  await prisma.scan.update({
    where: { id: scanId },
    data: {
      autoResolvedCount: delta.resolvedCount,
      newFindingCount: delta.newFindingIds.length,
    },
  });

  log.info(
    {
      projectId,
      baselineScanId: delta.baseline.scanId,
      baselineScanType: delta.baseline.scanType,
      resolved: delta.resolvedCount,
      new: delta.newFindingIds.length,
      persisting: delta.persistingFindingIds.length,
    },
    "Scan delta computed against history baseline",
  );

  return {
    resolved: delta.resolvedCount,
    newCount: delta.newFindingIds.length,
    persistingCount: delta.persistingFindingIds.length,
  };
}

// ─── Previous-scan fingerprint set (used by the previous-findings UI) ───────

export async function getPreviousScanFingerprintSet(
  scanId: string,
  projectId: string,
): Promise<Set<string> | null> {
  const currentScan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: { createdAt: true, scanType: true, projectId: true },
  });
  if (!currentScan || currentScan.projectId !== projectId) return null;

  const { pickBaseline } = await import("@/lib/scan-delta");
  const candidates = await prisma.scanSnapshot.findMany({
    where: { projectId, findingsCaptured: true, scanId: { not: scanId }, completedAt: { lt: currentScan.createdAt } },
    orderBy: { completedAt: "desc" },
    take: 25,
    select: { id: true, scanId: true, scanType: true, completedAt: true },
  });
  const baseline = pickBaseline(candidates, { scanId, scanType: currentScan.scanType, createdAt: currentScan.createdAt });
  if (!baseline) return null;

  const previousFindings = await prisma.scanSnapshotFinding.findMany({
    where: { snapshotId: baseline.id },
    select: { fingerprint: true },
  });
  return new Set(previousFindings.map((f) => f.fingerprint));
}
