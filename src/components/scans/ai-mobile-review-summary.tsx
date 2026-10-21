"use client";

import { Smartphone } from "lucide-react";
import { MOBILE_PLATFORM_LABELS, type MobilePlatform } from "@/lib/mobile-platform";

/** Scan.scannerProgress.AI_MOBILE_REVIEW once the review has run (see lib/mobile-ai-review). */
interface AiMobileReviewRecord {
  status?: string;
  outcome?: "completed" | "skipped" | "failed";
  platform?: MobilePlatform;
  model?: string;
  findings?: number;
  notInspected?: string;
  note?: string;
  decompiler?: string | null;
  inputTokens?: number;
  outputTokens?: number;
  durationMs?: number;
}

function formatTokens(n: number | undefined): string | null {
  if (n === undefined) return null;
  return n >= 1000 ? `${(n / 1000).toFixed(n >= 100_000 ? 0 : 1)}k` : String(n);
}

/** What the GPT-6 Astra review of an uploaded mobile app did, or why it did not run. */
export function AiMobileReviewSummary({ scannerProgress }: { scannerProgress: unknown }) {
  const record =
    scannerProgress && typeof scannerProgress === "object"
      ? ((scannerProgress as Record<string, unknown>).AI_MOBILE_REVIEW as AiMobileReviewRecord | undefined)
      : undefined;
  if (!record || record.status !== "DONE") return null;

  const platform = record.platform ? MOBILE_PLATFORM_LABELS[record.platform] : "Mobile";
  const model = record.model ?? "GPT-6 Astra";
  const tokensIn = formatTokens(record.inputTokens);
  const tokensOut = formatTokens(record.outputTokens);
  const usage = [
    record.durationMs ? `took about ${Math.max(1, Math.round(record.durationMs / 60_000))} min` : null,
    tokensIn && tokensOut ? `used ${tokensIn} input / ${tokensOut} output tokens` : null,
  ].filter(Boolean);
  const usageText = usage.length > 0 ? ` It ${usage.join(" and ")}.` : "";

  let heading: string;
  if (record.outcome === "completed") {
    const n = record.findings ?? 0;
    heading = `${platform} app review (${model}): ${n} finding${n === 1 ? "" : "s"}`;
  } else if (record.outcome === "skipped") {
    heading = `${platform} app review (${model}) did not run`;
  } else {
    heading = `${platform} app review (${model}) failed`;
  }

  return (
    <div className="overflow-hidden rounded-xl border border-sky-200 bg-gradient-to-br from-sky-50/70 to-white shadow-sm dark:border-sky-900/40 dark:from-sky-950/20 dark:to-slate-950">
      <div className="flex items-start gap-3 px-5 py-4 sm:px-6">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-sky-100 dark:bg-sky-900/40">
          <Smartphone className="h-4 w-4 text-sky-700 dark:text-sky-300" aria-hidden />
        </div>
        <div className="min-w-0 space-y-2 text-sm">
          <p className="font-semibold text-slate-900 dark:text-slate-100">{heading}</p>
          {record.outcome === "completed" ? (
            <>
              <p className="text-xs text-slate-600 dark:text-slate-400">
                Reviewed in an OpenAI-hosted container without network access
                {record.decompiler ? ", decompiled with jadx" : ""}. Findings show as{" "}
                <code className="rounded bg-muted px-1">app!/file</code> with the evidence the model traced.
                {usageText}
              </p>
              {record.notInspected?.trim() && (
                <p className="text-xs text-amber-800 dark:text-amber-300">Not inspected: {record.notInspected.trim()}</p>
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
