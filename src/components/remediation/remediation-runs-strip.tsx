"use client";

import Link from "next/link";
import useSWR from "swr";
import { Bot, ExternalLink, Loader2 } from "lucide-react";
import { jsonFetcher } from "@/lib/fetcher";

interface RunSummary {
  id: string;
  status: string;
  prUrl: string | null;
  fixedCount: number;
  failedCount: number;
  total: number;
  createdAt: string;
}

const LABEL: Record<string, string> = {
  QUEUED: "queued",
  RUNNING: "running",
  COMPLETED: "completed",
  PARTIAL: "partially fixed",
  FAILED: "failed",
  CANCELLED: "cancelled",
};

/** Latest AI remediation run for a scan, with links to the live view and PR. */
export function RemediationRunsStrip({ scanId }: { scanId: string }) {
  const { data } = useSWR<{ runs: RunSummary[] }>(
    `/api/scans/${scanId}/remediation`,
    jsonFetcher,
    { refreshInterval: (d) => (d?.runs?.some((r) => r.status === "QUEUED" || r.status === "RUNNING") ? 5000 : 0) },
  );
  const latest = data?.runs?.[0];
  if (!latest) return null;
  const active = latest.status === "QUEUED" || latest.status === "RUNNING";

  return (
    <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border bg-muted/30 px-4 py-2 text-sm">
      {active ? (
        <Loader2 className="h-4 w-4 animate-spin text-blue-600 dark:text-blue-400" aria-hidden />
      ) : (
        <Bot className="h-4 w-4 text-primary" aria-hidden />
      )}
      <span>
        AI remediation {LABEL[latest.status] ?? latest.status.toLowerCase()}
        {!active && ` — ${latest.fixedCount}/${latest.total} fixed`}
      </span>
      <Link href={`/remediation/${latest.id}`} className="text-primary hover:underline">
        {active ? "Watch live" : "View run"}
      </Link>
      {latest.prUrl && (
        <a
          href={latest.prUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-primary hover:underline"
        >
          Pull request <ExternalLink className="h-3 w-3" aria-hidden />
        </a>
      )}
    </div>
  );
}
