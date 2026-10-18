/** Per-scanner progress as the worker records it on `Scan.scannerProgress`. */
export type ScannerProgressMap = Record<
  string,
  { status: string; filesCompleted?: number; filesTotal?: number }
>;

/**
 * Approximate completion percentage of a queued or running scan, from the
 * per-scanner progress the worker reports. Shown by the scan page and the MCP
 * server; never reaches 100 until the scan has finished.
 */
export function computeScanProgress(
  scannerProgress: ScannerProgressMap | null | undefined,
  status: string,
): number {
  if (status === "QUEUED") return 5;
  if (!scannerProgress || Object.keys(scannerProgress).length === 0) return 10;

  const entries = Object.values(scannerProgress);
  const done = entries.filter((s) => s.status === "DONE").length;
  const total = Math.max(entries.length + 1, 3);

  // If any scanner has file-level progress, use it for finer granularity
  let fileProgress = 0;
  let hasFileProgress = false;
  for (const s of entries) {
    if (s.status === "DONE") {
      fileProgress += 1;
    } else if (s.filesTotal && s.filesTotal > 0) {
      hasFileProgress = true;
      fileProgress += (s.filesCompleted || 0) / s.filesTotal;
    }
  }

  if (hasFileProgress) {
    // Weighted: file-level progress across all known scanners
    return Math.min(95, Math.round(10 + (fileProgress / total) * 85));
  }

  // Fallback: count done scanners
  return Math.min(95, Math.round(10 + (done / total) * 85));
}
