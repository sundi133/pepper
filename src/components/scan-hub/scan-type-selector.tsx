"use client";

import { Label } from "@/components/ui/label";
import { MANUAL_SCAN_TYPE_OPTIONS } from "@/lib/scan-types";
import type { ScanJobData } from "@/lib/queue";
import { cn } from "@/lib/utils";

type ScanTypeSelectorProps = {
  value: ScanJobData["scanType"];
  onChange: (value: ScanJobData["scanType"]) => void;
  className?: string;
  compact?: boolean;
};

const ALL_SCANNERS_LIST =
  "SAST · SCA · Secrets · IaC · Zero-day · Container · Kubernetes";

const SCAN_DESCRIPTIONS: Record<string, string> = {
  FULL: "All scanners run across the full codebase.",
  QUICK: "Pattern-based SAST scan only — fast results.",
  INCREMENTAL: "Only scan files changed relative to a baseline.",
};

export function ScanTypeSelector({
  value,
  onChange,
  className,
  compact = false,
}: ScanTypeSelectorProps) {
  return (
    <div className={cn("space-y-2", className)}>
      <Label className="text-xs font-medium text-slate-700 dark:text-slate-300">
        Scan mode
      </Label>
      <div className="flex flex-wrap gap-2">
        {MANUAL_SCAN_TYPE_OPTIONS.map((option) => {
          const active = value === option.value;
          return (
            <button
              key={option.value}
              type="button"
              onClick={() => onChange(option.value)}
              className={cn(
                "flex items-center gap-2 rounded-lg border px-3.5 py-2 text-sm font-medium transition-all",
                compact && "px-2.5 py-1.5 text-xs",
                active
                  ? "border-indigo-200 bg-indigo-50 text-indigo-700 shadow-sm dark:border-indigo-700/60 dark:bg-indigo-950/30 dark:text-indigo-300"
                  : "border-slate-200 bg-white text-slate-600 hover:border-indigo-200 hover:bg-indigo-50/50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400",
              )}
              aria-pressed={active}
            >
              <span className="text-xs font-semibold">{option.label}</span>
            </button>
          );
        })}
      </div>
      <p className="text-xs leading-relaxed text-slate-500 dark:text-slate-400">
        {value === "FULL" ? (
          <>
            <span className="font-medium text-slate-700 dark:text-slate-300">All scanners:</span>{" "}
            {ALL_SCANNERS_LIST}. Respects LLM Config and org settings.
          </>
        ) : (
          SCAN_DESCRIPTIONS[value] || ""
        )}
      </p>
    </div>
  );
}
