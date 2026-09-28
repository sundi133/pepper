"use client";

import { useState } from "react";
import useSWR from "swr";
import { ArrowRight, ExternalLink, Loader2 } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { jsonFetcher } from "@/lib/fetcher";

export interface CompareScanOption {
  scanId: string;
  completedAt: string;
  commitSha: string | null;
  comparable: boolean;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface CompareItem {
  title: string;
  severity: string;
  status: string;
  scanner: string;
  filePath: string | null;
  startLine: number | null;
  ruleId: string | null;
  cweId: string | null;
  cveId: string | null;
  fixedBy?: { id: string; prUrl: string | null; prNumber: number | null } | null;
  previousSeverity?: string | null;
  previousLine?: number | null;
}

interface VersionMeta {
  scanId: string;
  completedAt: string;
  commitSha: string | null;
  totals: { critical: number; high: number; medium: number; low: number; info: number };
}

interface CompareResponse {
  base: VersionMeta;
  target: VersionMeta;
  available: boolean;
  reason?: string;
  summary?: {
    fixed: number;
    introduced: number;
    persisting: number;
    moved: number;
    reRated: number;
    suppressed: number;
    fixedByAi: number;
  };
  bySeverity?: Record<string, { fixed: number; introduced: number; persisting: number }>;
  byFile?: Array<{ filePath: string; fixed: number; introduced: number; net: number }>;
  fixed?: CompareItem[];
  introduced?: CompareItem[];
  persisting?: CompareItem[];
}

const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: "#d03b3b",
  HIGH: "#ec835a",
  MEDIUM: "#fab219",
  LOW: "#8a8983",
  INFO: "#b8b7b1",
};

const TABS = [
  { key: "fixed", label: "Fixed" },
  { key: "introduced", label: "New" },
  { key: "persisting", label: "Still present" },
] as const;
type TabKey = (typeof TABS)[number]["key"];

function sumOf(t: { critical: number; high: number; medium: number; low: number }): number {
  return t.critical + t.high + t.medium + t.low;
}

function label(o: CompareScanOption): string {
  const d = new Date(o.completedAt).toLocaleDateString(undefined, { month: "short", day: "numeric" });
  return `${d}${o.commitSha ? ` · ${o.commitSha.slice(0, 7)}` : ""} · ${sumOf(o)} findings`;
}

function titleCase(s: string): string {
  return s.charAt(0) + s.slice(1).toLowerCase();
}

function SeverityLabel({ severity }: { severity: string }) {
  return (
    <span className="inline-flex w-20 shrink-0 items-center gap-1.5 text-xs text-muted-foreground">
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEVERITY_DOT[severity] ?? SEVERITY_DOT.INFO }} aria-hidden />
      {titleCase(severity)}
    </span>
  );
}

function Row({ item, tab }: { item: CompareItem; tab: TabKey }) {
  const id = item.ruleId ?? item.cveId ?? item.cweId;
  return (
    <li className="flex items-start gap-3 px-4 py-3">
      <SeverityLabel severity={item.severity} />
      <div className="min-w-0 flex-1 space-y-0.5">
        <p className="text-[13px] leading-snug">{item.title}</p>
        <p className="truncate font-mono text-[11px] text-muted-foreground">
          {item.filePath ?? "—"}
          {item.startLine ? `:${item.startLine}` : ""}
          {id ? `  ·  ${id}` : ""}
        </p>
      </div>
      <div className="flex shrink-0 flex-col items-end gap-1 text-[11px] text-muted-foreground">
        {tab === "fixed" && item.fixedBy?.prUrl && (
          <a
            href={item.fixedBy.prUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded-md bg-emerald-500/10 px-1.5 py-0.5 font-medium text-emerald-700 hover:underline dark:text-emerald-300"
          >
            AI fix {item.fixedBy.prNumber ? `#${item.fixedBy.prNumber}` : "PR"}
            <ExternalLink className="h-3 w-3" aria-hidden />
          </a>
        )}
        {item.previousSeverity && <span>was {titleCase(item.previousSeverity)}</span>}
        {item.previousLine != null && <span>moved from line {item.previousLine}</span>}
        {item.status !== "OPEN" && tab !== "fixed" && <span>{titleCase(item.status.replace("_", " "))}</span>}
      </div>
    </li>
  );
}

export function ScanCompare({
  projectId,
  scans,
  baseId,
  targetId,
  onChange,
}: {
  projectId: string;
  /** Newest first. */
  scans: CompareScanOption[];
  baseId: string | null;
  targetId: string | null;
  onChange: (baseId: string, targetId: string) => void;
}) {
  const comparable = scans.filter((s) => s.comparable);
  const target = targetId ?? comparable[0]?.scanId ?? null;
  const base = baseId ?? comparable.find((s) => s.scanId !== target)?.scanId ?? null;
  const [tab, setTab] = useState<TabKey>("fixed");

  const key =
    base && target && base !== target
      ? `/api/dashboard/trends/compare?${new URLSearchParams({ project: projectId, base, target })}`
      : null;
  const { data, error, isLoading } = useSWR<CompareResponse>(key, jsonFetcher, { keepPreviousData: true });

  if (scans.length < 2) {
    return (
      <p className="rounded-xl border border-dashed border-border/70 px-5 py-6 text-center text-sm text-muted-foreground">
        Run at least two scans of this repository to compare versions.
      </p>
    );
  }

  const list = data?.[tab] ?? [];
  const counts = data?.summary;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={base ?? undefined} onValueChange={(v) => onChange(v, target ?? v)}>
          <SelectTrigger className="h-9 w-72" aria-label="Baseline scan">
            <SelectValue placeholder="Baseline scan" />
          </SelectTrigger>
          <SelectContent>
            {scans.map((s) => (
              <SelectItem key={s.scanId} value={s.scanId} disabled={!s.comparable || s.scanId === target}>
                {label(s)}
                {!s.comparable ? " (totals only)" : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <ArrowRight className="h-4 w-4 text-muted-foreground" aria-hidden />
        <Select value={target ?? undefined} onValueChange={(v) => onChange(base ?? v, v)}>
          <SelectTrigger className="h-9 w-72" aria-label="Compared scan">
            <SelectValue placeholder="Compare with" />
          </SelectTrigger>
          <SelectContent>
            {scans.map((s) => (
              <SelectItem key={s.scanId} value={s.scanId} disabled={!s.comparable || s.scanId === base}>
                {label(s)}
                {!s.comparable ? " (totals only)" : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {isLoading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" aria-label="Comparing" />}
      </div>

      {comparable.length < 2 && (
        <p className="text-xs text-muted-foreground">
          Older scans only have totals. Every scan from now on records its findings, so versions can be compared in full.
        </p>
      )}
      {error && <p className="text-sm text-red-600 dark:text-red-400">{(error as Error).message}</p>}
      {data && !data.available && <p className="rounded-xl bg-muted/50 px-5 py-4 text-sm text-muted-foreground">{data.reason}</p>}

      {data?.available && counts && (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-xl border border-border/70 bg-card px-4 py-4">
              <p className="text-xs text-muted-foreground">Fixed</p>
              <p className="mt-1 text-2xl font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">{counts.fixed}</p>
              <p className="text-xs text-muted-foreground">
                {counts.fixedByAi ? `${counts.fixedByAi} by AI fix PRs` : "no longer detected"}
              </p>
            </div>
            <div className="rounded-xl border border-border/70 bg-card px-4 py-4">
              <p className="text-xs text-muted-foreground">New</p>
              <p className={`mt-1 text-2xl font-semibold tabular-nums ${counts.introduced ? "text-red-600 dark:text-red-400" : ""}`}>
                {counts.introduced}
              </p>
              <p className="text-xs text-muted-foreground">introduced since the baseline</p>
            </div>
            <div className="rounded-xl border border-border/70 bg-card px-4 py-4">
              <p className="text-xs text-muted-foreground">Still present</p>
              <p className="mt-1 text-2xl font-semibold tabular-nums">{counts.persisting}</p>
              <p className="text-xs text-muted-foreground">
                {[
                  counts.moved ? `${counts.moved} moved` : "",
                  counts.reRated ? `${counts.reRated} re-rated` : "",
                  counts.suppressed ? `${counts.suppressed} suppressed not counted` : "",
                ]
                  .filter(Boolean)
                  .join(" · ") || "unchanged"}
              </p>
            </div>
          </div>

          <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_280px]">
            <div className="min-w-0 overflow-hidden rounded-xl border border-border/70 bg-card">
              <div role="tablist" aria-label="Finding changes" className="flex gap-1 border-b border-border/60 px-2 pt-2">
                {TABS.map((t) => {
                  const n = counts[t.key];
                  const active = tab === t.key;
                  return (
                    <button
                      key={t.key}
                      role="tab"
                      aria-selected={active}
                      type="button"
                      onClick={() => setTab(t.key)}
                      className={`-mb-px border-b-2 px-3 pb-2 pt-1 text-[13px] transition-colors ${active ? "border-foreground text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
                    >
                      {t.label} <span className="tabular-nums text-muted-foreground">{n}</span>
                    </button>
                  );
                })}
              </div>
              {list.length ? (
                <ul className="max-h-[480px] divide-y divide-border/50 overflow-y-auto">
                  {list.map((item, i) => (
                    <Row key={`${item.filePath}-${item.startLine}-${item.title}-${i}`} item={item} tab={tab} />
                  ))}
                </ul>
              ) : (
                <p className="px-4 py-8 text-center text-sm text-muted-foreground">
                  {tab === "fixed" ? "Nothing fixed between these scans." : tab === "introduced" ? "No new findings." : "No findings in common."}
                </p>
              )}
              {counts[tab] > list.length && (
                <p className="border-t border-border/60 px-4 py-2 text-xs text-muted-foreground">
                  Showing {list.length} of {counts[tab]}.
                </p>
              )}
            </div>

            <div className="space-y-5">
              <div className="rounded-xl border border-border/70 bg-card px-4 py-3">
                <table className="w-full text-xs">
                  <caption className="pb-2 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                    By severity
                  </caption>
                  <thead className="text-muted-foreground">
                    <tr>
                      <th className="py-1 text-left font-normal" />
                      <th className="py-1 text-right font-normal">Fixed</th>
                      <th className="py-1 text-right font-normal">New</th>
                      <th className="py-1 text-right font-normal">Still</th>
                    </tr>
                  </thead>
                  <tbody className="tabular-nums">
                    {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => {
                      const v = data.bySeverity?.[s] ?? { fixed: 0, introduced: 0, persisting: 0 };
                      return (
                        <tr key={s}>
                          <td className="py-1">
                            <SeverityLabel severity={s} />
                          </td>
                          <td className="py-1 text-right">{v.fixed}</td>
                          <td className="py-1 text-right">{v.introduced}</td>
                          <td className="py-1 text-right">{v.persisting}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {!!data.byFile?.length && (
                <div className="rounded-xl border border-border/70 bg-card px-4 py-3">
                  <p className="pb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">Most changed files</p>
                  <ul className="space-y-1.5 text-xs">
                    {data.byFile.slice(0, 6).map((f) => (
                      <li key={f.filePath} className="flex items-center justify-between gap-3">
                        <span className="truncate font-mono text-[11px] text-muted-foreground" title={f.filePath}>
                          {f.filePath}
                        </span>
                        <span className="shrink-0 tabular-nums">
                          {f.fixed ? <span className="text-emerald-600 dark:text-emerald-400">−{f.fixed}</span> : null}
                          {f.fixed && f.introduced ? " " : null}
                          {f.introduced ? <span className="text-red-600 dark:text-red-400">+{f.introduced}</span> : null}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
