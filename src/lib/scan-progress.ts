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
 * The agent deep scan's per-scanner progress key (scanners/mobile-agent's
 * ScannerPlugin.name). Kept as a literal here so this shared, client-safe module
 * does not import the server-only scanner (which pulls in the E2B SDK).
 */
export const AGENT_SCAN_PROGRESS_KEY = "agent-scan";

/**
 * The deduped, PERSISTED agent-deep-scan finding count — the number the worker
 * wrote for the agent scanner after the shared FindingDeduplicator ran, so it
 * matches the Findings tab exactly. null when the agent scanner has no recorded
 * count yet. Use this for the banner rather than the agent's own pre-dedup
 * "reported" number.
 */
export function agentScanKeptCount(
  scannerProgress: Record<string, unknown> | null | undefined,
): number | null {
  const entry = scannerProgress?.[AGENT_SCAN_PROGRESS_KEY];
  if (entry && typeof entry === "object") {
    const n = (entry as { findingsCount?: unknown }).findingsCount;
    if (typeof n === "number") return n;
  }
  return null;
}

/** Scan.scannerProgress.AGENT_SCAN — the agent deep scan's status/outcome. */
export interface AgentScanRecord {
  status?: string;
  outcome?: "completed" | "incomplete" | "failed" | "skipped";
  sandboxId?: string;
  /** Raw count the agent reported (pre-dedup); shown only as a secondary note. */
  reported?: number;
  note?: string;
}

/** The view the agent-scan summary card renders, or null when there is nothing to show. */
export interface AgentScanSummaryView {
  outcome: AgentScanRecord["outcome"];
  heading: string;
  /** "warning" = a failed run (never a clean result); "info" = ran / did not run. */
  tone: "info" | "warning";
  failed: boolean;
  /** The agent ran to a usable end (completed or stopped early with findings). */
  completed: boolean;
  kept: number;
  reported?: number;
  dedupedAway: number;
  sandboxId?: string;
  note?: string;
}

/**
 * Decides the agent-deep-scan summary view from `Scan.scannerProgress`. Pure and
 * client-safe so both the scan page and tests share one source of truth. Crucially,
 * a FAILED run is represented distinctly (tone "warning", a heading that says
 * failed) from a run that completed with zero findings (tone "info") — a failed
 * deep scan must never read as a clean result. Returns null until the agent run
 * has finished (status DONE) or when there is no agent run at all.
 */
export function agentScanSummaryView(
  scannerProgress: Record<string, unknown> | null | undefined,
): AgentScanSummaryView | null {
  const progress =
    scannerProgress && typeof scannerProgress === "object" ? scannerProgress : undefined;
  const record = progress?.AGENT_SCAN as AgentScanRecord | undefined;
  if (!record || record.status !== "DONE") return null;

  // The kept/persisted count (post-dedup) matches the Findings tab exactly; the
  // agent's own "reported" number is pre-dedup and shown only as context.
  const kept = agentScanKeptCount(progress) ?? record.reported ?? 0;
  const reported = record.reported;
  const dedupedAway = typeof reported === "number" && reported > kept ? reported - kept : 0;
  const failed = record.outcome === "failed";
  const completed = record.outcome === "completed" || record.outcome === "incomplete";

  let heading: string;
  if (record.outcome === "completed") {
    heading = `Agent deep scan: ${kept} finding${kept === 1 ? "" : "s"}`;
  } else if (record.outcome === "incomplete") {
    heading = `Agent deep scan stopped early: ${kept} finding${kept === 1 ? "" : "s"}`;
  } else if (record.outcome === "skipped") {
    heading = "Agent deep scan did not run";
  } else {
    heading = "Agent deep scan failed";
  }

  return {
    outcome: record.outcome,
    heading,
    tone: failed ? "warning" : "info",
    failed,
    completed,
    kept,
    reported,
    dedupedAway,
    sandboxId: record.sandboxId,
    note: record.note,
  };
}

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
