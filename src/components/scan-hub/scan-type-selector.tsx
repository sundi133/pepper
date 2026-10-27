"use client";

import { Check } from "lucide-react";
import { Label } from "@/components/ui/label";
import {
  SCAN_MODULES,
  SCAN_MODULE_IDS,
  normalizeScanSelection,
  scanModeLabel,
  selectedScanModules,
  type ScanModuleId,
} from "@/lib/scan-types";
import type { ScanJobData } from "@/lib/queue";
import { cn } from "@/lib/utils";

type ScanTypeSelectorProps = {
  value: ScanJobData["scanType"];
  /** Scanner groups combined on the scan; empty = what `value` implies. */
  modules?: readonly string[];
  onChange: (value: ScanJobData["scanType"], modules: ScanModuleId[]) => void;
  className?: string;
  compact?: boolean;
};

const chip = (active: boolean, compact: boolean) =>
  cn(
    "flex items-center gap-1.5 rounded-lg border px-3.5 py-2 text-xs font-semibold transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
    compact && "px-2.5 py-1.5",
    active
      ? "border-indigo-200 bg-indigo-50 text-indigo-700 shadow-sm dark:border-indigo-700/60 dark:bg-indigo-950/30 dark:text-indigo-300"
      : "border-slate-200 bg-white text-slate-600 hover:border-indigo-200 hover:bg-indigo-50/50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400",
  );

/**
 * Pick any combination of scanners, plus whether to scan only changed files.
 * "All" is every scanner; clicking a scanner while "All" is on narrows to it,
 * and removing the last selected scanner goes back to "All".
 */
export function ScanTypeSelector({
  value,
  modules,
  onChange,
  className,
  compact = false,
}: ScanTypeSelectorProps) {
  const diffOnly = value === "INCREMENTAL";
  const picked = selectedScanModules(value, modules);
  const allPicked = picked.length === SCAN_MODULE_IDS.length;

  const emit = (nextModules: ScanModuleId[], nextDiff = diffOnly) => {
    const next = normalizeScanSelection(nextDiff ? "INCREMENTAL" : "FULL", nextModules);
    onChange(next.scanType, next.scanModules);
  };

  const toggleModule = (id: ScanModuleId) => {
    if (allPicked) return emit([id]);
    const next = picked.includes(id) ? picked.filter((m) => m !== id) : [...picked, id];
    emit(next.length === 0 ? [...SCAN_MODULE_IDS] : next);
  };

  const pickedDetails = SCAN_MODULES.filter((m) => picked.includes(m.id));

  return (
    <div className={cn("space-y-2", className)}>
      <Label className="text-xs font-medium text-slate-700 dark:text-slate-300">
        Scanners <span className="font-normal text-slate-400">(pick one or more)</span>
      </Label>
      <div className="flex flex-wrap gap-2" role="group" aria-label="Scanners">
        <button
          type="button"
          onClick={() => emit([...SCAN_MODULE_IDS])}
          className={chip(allPicked, compact)}
          aria-pressed={allPicked}
        >
          All
        </button>
        {SCAN_MODULES.map((m) => {
          const active = !allPicked && picked.includes(m.id);
          return (
            <button
              key={m.id}
              type="button"
              onClick={() => toggleModule(m.id)}
              className={chip(active, compact)}
              aria-pressed={active}
              title={m.description}
            >
              {active && <Check className="h-3 w-3" aria-hidden />}
              {m.label}
            </button>
          );
        })}
      </div>

      <label className="flex cursor-pointer items-start gap-2 pt-1 text-xs text-slate-600 dark:text-slate-400">
        <input
          type="checkbox"
          checked={diffOnly}
          onChange={(e) => emit(picked, e.target.checked)}
          className="mt-0.5 h-3.5 w-3.5 rounded border-slate-300 accent-indigo-600"
        />
        <span>
          <span className="font-semibold text-slate-700 dark:text-slate-300">PR Diff</span>
          {" — "}only scan files changed in a pull request or between two commits.
        </span>
      </label>

      <div className="space-y-1 text-xs leading-relaxed text-slate-500 dark:text-slate-400">
        <p>
          <span className="font-medium text-slate-700 dark:text-slate-300">Will run:</span>{" "}
          {scanModeLabel(value, modules)}
          {allPicked ? " (SAST, SCA, Secrets, IaC, Zero-day, Container, Kubernetes)" : ""}.
          {" "}Respects LLM Config and org settings.
        </p>
        {!allPicked && (
          <ul className="space-y-0.5">
            {pickedDetails.map((m) => (
              <li key={m.id}>
                <span className="font-medium text-slate-600 dark:text-slate-300">{m.label}:</span>{" "}
                {m.description}
                {m.needsAi ? " Needs LLM SAST enabled." : ""}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
