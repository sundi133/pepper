"use client";

import { Boxes } from "lucide-react";
import { agentScanKeptCount } from "@/lib/scan-progress";

/** Scan.scannerProgress.AGENT_SCAN — the agent deep scan's status/outcome (see scanners/mobile-agent + the worker). */
interface AgentScanRecord {
  status?: string;
  outcome?: "completed" | "incomplete" | "failed" | "skipped";
  sandboxId?: string;
  /** Raw count the agent reported (pre-dedup); shown only as a secondary note. */
  reported?: number;
  note?: string;
}

/** What the agent deep scan of an uploaded binary did, or why it did not run. */
export function AgentScanSummary({ scannerProgress }: { scannerProgress: unknown }) {
  const progress =
    scannerProgress && typeof scannerProgress === "object"
      ? (scannerProgress as Record<string, unknown>)
      : undefined;
  const record = progress?.AGENT_SCAN as AgentScanRecord | undefined;
  if (!record || record.status !== "DONE") return null;

  // The kept/persisted count (post-dedup) matches the Findings tab exactly; the
  // agent's own "reported" number is pre-dedup and shown only as context.
  const kept = agentScanKeptCount(progress) ?? record.reported ?? 0;
  const reported = record.reported;
  const dedupedAway = typeof reported === "number" && reported > kept ? reported - kept : 0;

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

  const completed = record.outcome === "completed" || record.outcome === "incomplete";

  return (
    <div className="overflow-hidden rounded-xl border border-indigo-200 bg-gradient-to-br from-indigo-50/70 to-white shadow-sm dark:border-indigo-900/40 dark:from-indigo-950/20 dark:to-slate-950">
      <div className="flex items-start gap-3 px-5 py-4 sm:px-6">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-indigo-100 dark:bg-indigo-900/40">
          <Boxes className="h-4 w-4 text-indigo-700 dark:text-indigo-300" aria-hidden />
        </div>
        <div className="min-w-0 space-y-2 text-sm">
          <p className="font-semibold text-slate-900 dark:text-slate-100">{heading}</p>
          {completed ? (
            <>
              <p className="text-xs text-slate-600 dark:text-slate-400">
                glm-5.3 decompiled and inspected the upload in an ephemeral E2B sandbox
                {record.sandboxId ? ` (${record.sandboxId})` : ""}. Findings show as{" "}
                <code className="rounded bg-muted px-1">app!/file</code> with the evidence the model traced.
                {record.note ? ` ${record.note}` : ""}
              </p>
              {dedupedAway > 0 && (
                <p className="text-xs text-slate-500 dark:text-slate-500">
                  {reported} reported → {kept} kept after de-duplication.
                </p>
              )}
            </>
          ) : (
            record.note && <p className="break-words text-xs text-amber-800 dark:text-amber-300">{record.note}</p>
          )}
        </div>
      </div>
    </div>
  );
}
