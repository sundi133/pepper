"use client";

import { Boxes, AlertTriangle } from "lucide-react";
import { agentScanSummaryView } from "@/lib/scan-progress";

/** What the agent deep scan of an uploaded binary did, or why it did not run. */
export function AgentScanSummary({ scannerProgress }: { scannerProgress: unknown }) {
  const view = agentScanSummaryView(
    scannerProgress && typeof scannerProgress === "object"
      ? (scannerProgress as Record<string, unknown>)
      : undefined,
  );
  if (!view) return null;

  const { heading, failed, completed, kept, reported, dedupedAway, sandboxId, note } = view;

  // A failed run gets warning (amber) chrome so it can never be mistaken for the
  // indigo "ran and found nothing" card; "skipped"/"incomplete" keep the
  // neutral indigo styling (the agent either did not run or still reported).
  const cardClass = failed
    ? "overflow-hidden rounded-xl border border-amber-300 bg-gradient-to-br from-amber-50 to-white shadow-sm dark:border-amber-900/50 dark:from-amber-950/20 dark:to-slate-950"
    : "overflow-hidden rounded-xl border border-indigo-200 bg-gradient-to-br from-indigo-50/70 to-white shadow-sm dark:border-indigo-900/40 dark:from-indigo-950/20 dark:to-slate-950";
  const iconWrapClass = failed
    ? "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-100 dark:bg-amber-900/40"
    : "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-indigo-100 dark:bg-indigo-900/40";
  const headingClass = failed
    ? "font-semibold text-amber-800 dark:text-amber-300"
    : "font-semibold text-slate-900 dark:text-slate-100";

  return (
    <div className={cardClass}>
      <div className="flex items-start gap-3 px-5 py-4 sm:px-6">
        <div className={iconWrapClass}>
          {failed ? (
            <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400" aria-hidden />
          ) : (
            <Boxes className="h-4 w-4 text-indigo-700 dark:text-indigo-300" aria-hidden />
          )}
        </div>
        <div className="min-w-0 space-y-2 text-sm">
          <p className={headingClass}>{heading}</p>
          {completed ? (
            <>
              <p className="text-xs text-slate-600 dark:text-slate-400">
                glm-5.3 decompiled and inspected the upload in an ephemeral E2B sandbox
                {sandboxId ? ` (${sandboxId})` : ""}. Findings show as{" "}
                <code className="rounded bg-muted px-1">app!/file</code> with the evidence the model traced.
                {note ? ` ${note}` : ""}
              </p>
              {dedupedAway > 0 && (
                <p className="text-xs text-slate-500 dark:text-slate-500">
                  {reported} reported → {kept} kept after de-duplication.
                </p>
              )}
            </>
          ) : failed ? (
            <p className="break-words text-xs text-amber-800 dark:text-amber-300">
              The deep scan did not complete, so this upload was not reviewed — this is
              not a clean result.{note ? ` ${note}` : ""}
            </p>
          ) : (
            note && <p className="break-words text-xs text-amber-800 dark:text-amber-300">{note}</p>
          )}
        </div>
      </div>
    </div>
  );
}
