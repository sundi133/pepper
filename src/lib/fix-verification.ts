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

export function findingFingerprint(f: FingerprintInput): string {
  return [
    f.scanner,
    f.ruleId ?? f.cveId ?? f.cweId ?? normalizeFindingTitle(f.title),
    f.filePath ?? "",
    f.startLine != null ? Math.floor(f.startLine / 5) : 0,
  ].join(":");
}

// ─── Core logic ─────────────────────────────────────────────────────────────

export async function autoResolveFixedFindings(
  scanId: string,
  projectId: string,
  log: Logger,
): Promise<{ resolved: number; newCount: number; persistingCount: number }> {
  // Find the most recent completed scan for this project before this one
  const currentScan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: { createdAt: true },
  });
  if (!currentScan) return { resolved: 0, newCount: 0, persistingCount: 0 };

  const previousScan = await prisma.scan.findFirst({
    where: {
      projectId,
      status: "COMPLETED",
      id: { not: scanId },
      createdAt: { lt: currentScan.createdAt },
    },
    orderBy: { createdAt: "desc" },
    select: { id: true },
  });

  if (!previousScan) {
    // No prior scan — all findings have isNew = null (no comparison available)
    return { resolved: 0, newCount: 0, persistingCount: 0 };
  }

  // ── Step 1: Fetch all findings from the previous scan (all statuses) ──────
  // We include false positives and resolved too so the fingerprint set is
  // complete — we don't want to flag a previously-suppressed finding as "new".
  const previousFindings = await prisma.finding.findMany({
    where: { scanId: previousScan.id },
    select: {
      id: true,
      scanner: true,
      ruleId: true,
      cweId: true,
      cveId: true,
      filePath: true,
      startLine: true,
      title: true,
      status: true,
    },
  });

  const previousFingerprintSet = new Set(previousFindings.map(findingFingerprint));
  const previousOpenFingerprintSet = new Set(
    previousFindings
      .filter((f) => f.status === "OPEN" || f.status === "IN_PROGRESS")
      .map(findingFingerprint),
  );

  // ── Step 2: Fetch current scan findings ───────────────────────────────────
  const currentFindings = await prisma.finding.findMany({
    where: { scanId, status: { not: "FALSE_POSITIVE" } },
    select: {
      id: true,
      scanner: true,
      ruleId: true,
      cweId: true,
      cveId: true,
      filePath: true,
      startLine: true,
      title: true,
    },
  });

  // ── Step 3: Tag current findings as new vs. persisting ───────────────────
  const newIds: string[] = [];
  const persistingIds: string[] = [];

  for (const f of currentFindings) {
    const fp = findingFingerprint(f);
    if (previousFingerprintSet.has(fp)) {
      persistingIds.push(f.id);
    } else {
      newIds.push(f.id);
    }
  }

  // Batch-update isNew flags
  if (newIds.length > 0) {
    await prisma.finding.updateMany({
      where: { id: { in: newIds } },
      data: { isNew: true },
    });
  }
  if (persistingIds.length > 0) {
    await prisma.finding.updateMany({
      where: { id: { in: persistingIds } },
      data: { isNew: false },
    });
  }

  // ── Step 4: Auto-resolve findings from previous scan that are now gone ────
  // Only consider OPEN / IN_PROGRESS findings from the previous scan.
  const currentFingerprintSet = new Set(currentFindings.map(findingFingerprint));
  const previousOpenFindings = previousFindings.filter(
    (f) => f.status === "OPEN" || f.status === "IN_PROGRESS",
  );

  const resolvedIds = previousOpenFindings
    .filter((f) => !currentFingerprintSet.has(findingFingerprint(f)))
    .map((f) => f.id);

  if (resolvedIds.length > 0) {
    await prisma.finding.updateMany({
      where: { id: { in: resolvedIds } },
      data: {
        status: "RESOLVED",
        statusNote: `Auto-resolved: not detected in scan ${scanId}`,
        statusUpdatedAt: new Date(),
      },
    });
  }

  // Persist counts on the current scan
  await prisma.scan.update({
    where: { id: scanId },
    data: {
      autoResolvedCount: resolvedIds.length,
      newFindingCount: newIds.length,
    },
  });

  log.info(
    {
      resolved: resolvedIds.length,
      new: newIds.length,
      persisting: persistingIds.length,
      previousScanId: previousScan.id,
    },
    "Scan delta computed",
  );

  return {
    resolved: resolvedIds.length,
    newCount: newIds.length,
    persistingCount: persistingIds.length,
  };
}

// ─── Previous-scan fingerprint set (used by the previous-findings UI) ───────

export async function getPreviousScanFingerprintSet(
  scanId: string,
  projectId: string,
): Promise<Set<string> | null> {
  const currentScan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: { createdAt: true },
  });
  if (!currentScan) return null;

  const previousScan = await prisma.scan.findFirst({
    where: {
      projectId,
      status: "COMPLETED",
      id: { not: scanId },
      createdAt: { lt: currentScan.createdAt },
    },
    orderBy: { createdAt: "desc" },
    select: { id: true },
  });
  if (!previousScan) return null;

  const previousFindings = await prisma.finding.findMany({
    where: { scanId: previousScan.id },
    select: { scanner: true, ruleId: true, cweId: true, cveId: true, filePath: true, startLine: true, title: true },
  });

  return new Set(previousFindings.map(findingFingerprint));
}
