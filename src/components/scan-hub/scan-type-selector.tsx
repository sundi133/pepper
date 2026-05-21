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
  "SAST · SCA · Secrets · IaC · Zero-day · Container · DAST";

export function ScanTypeSelector({
  value,
  onChange,
  className,
  compact = false,
}: ScanTypeSelectorProps) {
  const selected = MANUAL_SCAN_TYPE_OPTIONS.find((o) => o.value === value);

  return (
    <div className={cn("space-y-2", className)}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Label className="text-xs font-medium text-slate-700 dark:text-slate-300">
          Scanners
        </Label>
        <span className="text-[11px] text-slate-500 dark:text-slate-400">
          Default: All
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {MANUAL_SCAN_TYPE_OPTIONS.map((option) => {
          const active = value === option.value;
          return (
            <button
              key={option.value}
              type="button"
              onClick={() => onChange(option.value)}
              className={cn(
                "rounded-full border px-2.5 py-1 text-xs font-medium transition-all",
                compact && "px-2 py-0.5 text-[11px]",
                active
                  ? "border-teal-500/60 bg-teal-500/10 text-teal-900 shadow-sm dark:text-teal-100"
                  : "border-slate-200/90 bg-white text-slate-600 hover:border-teal-400/40 hover:text-teal-800 dark:border-slate-700 dark:bg-slate-900/50 dark:text-slate-400",
              )}
              aria-pressed={active}
            >
              {option.label}
            </button>
          );
        })}
      </div>
      <p className="text-xs leading-relaxed text-slate-500 dark:text-slate-400">
        {value === "FULL" ? (
          <>
            <span className="font-medium text-slate-700 dark:text-slate-300">
              All scanners:
            </span>{" "}
            {ALL_SCANNERS_LIST}. Respects LLM Config and org settings for each
            engine.
          </>
        ) : (
          selected?.description
        )}
      </p>
    </div>
  );
}
