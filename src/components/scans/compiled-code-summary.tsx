"use client";

import { Binary } from "lucide-react";
import { decompilerLabel } from "@/lib/compiled-scan/finding-origin";

/** Scan.scannerProgress.DECOMPILE once the compiled-code scan has run (see lib/compiled-scan). */
interface DecompileRecord {
  status?: string;
  decompiled?: number;
  filesAdded?: number;
  truncated?: boolean;
  artifacts?: Array<{ artifact: string; tool?: string; files?: number; status?: string; note?: string }>;
  skipped?: Array<{ path: string; reason: string; detail?: string }>;
  skippedByReason?: Record<string, number>;
}

const REASON_LABELS: Record<string, string> = {
  dependency: "dependency",
  "build-output": "build output of scanned source",
  "source-present": "source already scanned",
  "third-party": "third-party library",
  native: "native code",
  unrecognized: "unrecognized format",
  "too-large": "too large",
  "artifact-limit": "artifact limit",
  "output-limit": "output limit",
  "time-limit": "time limit",
  "tool-missing": "decompiler missing",
  timeout: "timed out",
  failed: "decompile failed",
  disabled: "not scanned",
};

/** What a scan decompiled from compiled artifacts, and what it skipped and why. */
export function CompiledCodeSummary({ scannerProgress }: { scannerProgress: unknown }) {
  const record =
    scannerProgress && typeof scannerProgress === "object"
      ? ((scannerProgress as Record<string, unknown>).DECOMPILE as DecompileRecord | undefined)
      : undefined;
  if (!record || record.status !== "DONE") return null;
  const artifacts = record.artifacts ?? [];
  // Dependencies are skipped by design; list what a reader may want to act on.
  // The agent deep scan handoff is also dropped: when the agent owns a binary
  // upload the local decompile does nothing, and the "Agent deep scan" panel
  // below already explains it — this panel would just show a confusing
  // "0 artifacts decompiled … handled by the agent deep scan".
  const notes = (record.skipped ?? []).filter(
    (s) => s.reason !== "dependency" && !/agent deep scan/i.test(s.detail ?? ""),
  );
  const dependencySkips = record.skippedByReason?.dependency ?? 0;
  if (artifacts.length === 0 && notes.length === 0) return null;

  return (
    <div className="overflow-hidden rounded-xl border border-violet-200 bg-gradient-to-br from-violet-50/70 to-white shadow-sm dark:border-violet-900/40 dark:from-violet-950/20 dark:to-slate-950">
      <div className="flex items-start gap-3 px-5 py-4 sm:px-6">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-violet-100 dark:bg-violet-900/40">
          <Binary className="h-4 w-4 text-violet-700 dark:text-violet-300" aria-hidden />
        </div>
        <div className="min-w-0 space-y-2 text-sm">
          <p className="font-semibold text-slate-900 dark:text-slate-100">
            Compiled code: {record.decompiled ?? artifacts.length} artifact
            {(record.decompiled ?? artifacts.length) === 1 ? "" : "s"} decompiled,{" "}
            {record.filesAdded ?? 0} file{record.filesAdded === 1 ? "" : "s"} scanned
          </p>
          <p className="text-xs text-slate-600 dark:text-slate-400">
            Findings in decompiled code show as <code className="rounded bg-muted px-1">artifact!/file</code>;
            their line numbers refer to the decompiled source.
            {record.truncated ? " Some decompiled output was not scanned (output limit reached)." : ""}
          </p>
          {artifacts.length > 0 && (
            <ul className="space-y-0.5 text-xs text-slate-700 dark:text-slate-300">
              {artifacts.map((a) => (
                <li key={a.artifact} className="break-all">
                  <code>{a.artifact}</code> — {a.files ?? 0} files
                  {a.tool ? ` (${decompilerLabel(a.tool)})` : ""}
                  {a.note ? `; ${a.note}` : ""}
                </li>
              ))}
            </ul>
          )}
          {notes.length > 0 && (
            <ul className="space-y-0.5 text-xs text-amber-800 dark:text-amber-300">
              {notes.map((s) => (
                <li key={`${s.path}:${s.reason}`} className="break-all">
                  Skipped <code>{s.path}</code>: {REASON_LABELS[s.reason] ?? s.reason}
                  {s.detail ? ` — ${s.detail}` : ""}
                </li>
              ))}
            </ul>
          )}
          {dependencySkips > 0 && (
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {dependencySkips} artifact{dependencySkips === 1 ? "" : "s"} in dependency folders skipped (covered by SCA).
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
