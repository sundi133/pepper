/** Per-scanner progress as the worker records it on `Scan.scannerProgress`. */
export type ScannerProgressMap = Record<
  string,
  { status: string; filesCompleted?: number; filesTotal?: number }
>;

/**
 * Reserved key under `Scan.scannerProgress` holding the live model-reasoning
 * tails ({ scannerName: rollingText }), not a scanner status. It must be
 * excluded wherever the map is treated as per-scanner progress.
 */
export const REASONING_PROGRESS_KEY = "__reasoning__";

/**
 * The live model-reasoning tails the worker writes under
 * `scannerProgress.__reasoning__`, or null when there are none. Each value is a
 * rolling tail of that scanner's reasoning; the full trace is the AI_REASONING
 * artifact.
 */
export function reasoningTails(
  scannerProgress: Record<string, unknown> | null | undefined,
): Record<string, string> | null {
  const raw = scannerProgress?.[REASONING_PROGRESS_KEY];
  if (!raw || typeof raw !== "object") return null;
  const entries = Object.entries(raw as Record<string, unknown>).filter(
    ([, v]) => typeof v === "string" && v.trim().length > 0,
  ) as Array<[string, string]>;
  return entries.length > 0 ? Object.fromEntries(entries) : null;
}

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

  // The __reasoning__ entry is a live-reasoning store, not a scanner status.
  const entries = Object.entries(scannerProgress)
    .filter(([name]) => name !== REASONING_PROGRESS_KEY)
    .map(([, info]) => info);
  if (entries.length === 0) return 10;
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
