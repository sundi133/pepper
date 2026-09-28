"use client";

import { Suspense, useMemo, useState } from "react";
import useSWR from "swr";
import { jsonFetcher } from "@/lib/fetcher";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
} from "recharts";
import { ArrowDownRight, ArrowUpRight, ExternalLink, Minus } from "lucide-react";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
import { ScanCompare } from "@/components/trends/scan-compare";

type Sev = "critical" | "high" | "medium" | "low";
type Totals = Record<Sev | "info", number>;

interface DayPoint {
  date: string;
  critical: number | null;
  high: number | null;
  medium: number | null;
  low: number | null;
  info: number | null;
  scans: number;
  gateFailed: number;
}

interface FixImpact {
  runId: string;
  status: string;
  openedAt: string;
  prUrl: string | null;
  prNumber: number | null;
  fixed: number;
  failed: number;
  before: (Totals & { at: string }) | null;
  after: (Totals & { at: string }) | null;
}

interface TrendsResponse {
  days: number;
  series: DayPoint[];
  mttr: Record<string, { count: number; meanHours: number }>;
  projects: Array<{ id: string; name: string }>;
  comparison: {
    baseline: (Totals & { at: string }) | null;
    current: (Totals & { at: string }) | null;
    baselineLabel: "before_first_fix" | "window_start";
  };
  repo: {
    project: { id: string; name: string; repoUrl: string | null };
    remediations: FixImpact[];
    scans: Array<
      Totals & {
        scanId: string;
        comparable: boolean;
        scanType: string;
        completedAt: string;
        commitSha: string | null;
        gateResult: string;
      }
    >;
  } | null;
}

const SEVERITIES: Array<{ key: Sev; label: string; dot: string }> = [
  // Status palette steps; each dot always sits beside its text label.
  { key: "critical", label: "Critical", dot: "#d03b3b" },
  { key: "high", label: "High", dot: "#ec835a" },
  { key: "medium", label: "Medium", dot: "#fab219" },
  { key: "low", label: "Low", dot: "#8a8983" },
];

// Single-series chart color (categorical slot 1), stepped for dark mode.
const VIZ_VARS = "[--series-1:#2a78d6] dark:[--series-1:#3987e5] [--gate:#d03b3b]";
const AXIS_TICK = { fontSize: 11, fill: "var(--muted-foreground)" };

function sum(t: Pick<Totals, Sev>): number {
  return t.critical + t.high + t.medium + t.low;
}

function fmtDay(d: string): string {
  return new Date(`${d}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function fmtDate(iso: string): string {
  // A bare YYYY-MM-DD is a calendar day, not UTC midnight.
  const d = /^\d{4}-\d{2}-\d{2}$/.test(iso) ? new Date(`${iso}T00:00:00`) : new Date(iso);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

/** Signed change; fewer findings is good. */
function Delta({ from, to, size = "sm" }: { from: number; to: number; size?: "sm" | "md" }) {
  const d = to - from;
  const cls = size === "md" ? "text-sm" : "text-xs";
  if (d === 0) {
    return (
      <span className={`inline-flex items-center gap-0.5 ${cls} text-muted-foreground`}>
        <Minus className="h-3 w-3" aria-hidden /> no change
      </span>
    );
  }
  const better = d < 0;
  return (
    <span
      className={`inline-flex items-center gap-0.5 ${cls} font-medium ${better ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`}
    >
      {better ? <ArrowDownRight className="h-3.5 w-3.5" aria-hidden /> : <ArrowUpRight className="h-3.5 w-3.5" aria-hidden />}
      {Math.abs(d)} {better ? "fewer" : "more"}
    </span>
  );
}

function ChartTooltip({
  active,
  payload,
  label,
  fixes,
}: {
  active?: boolean;
  payload?: Array<{ payload: DayPoint & { total: number | null } }>;
  label?: string;
  fixes?: Map<string, FixImpact[]>;
}) {
  if (!active || !payload?.length || !label) return null;
  const p = payload[0].payload;
  const dayFixes = fixes?.get(label) ?? [];
  return (
    <div className="min-w-44 rounded-lg border border-border/70 bg-popover px-3 py-2.5 text-xs shadow-md">
      <p className="mb-1.5 font-medium text-foreground">{fmtDay(label)}</p>
      {p.total === null ? (
        <p className="text-muted-foreground">Not scanned yet</p>
      ) : (
        <>
          <p className="flex justify-between gap-4">
            <span className="text-muted-foreground">Findings</span>
            <span className="font-medium tabular-nums text-foreground">{p.total}</span>
          </p>
          {SEVERITIES.map((s) => (
            <p key={s.key} className="flex justify-between gap-4">
              <span className="inline-flex items-center gap-1.5 text-muted-foreground">
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.dot }} aria-hidden />
                {s.label}
              </span>
              <span className="tabular-nums text-foreground">{p[s.key] ?? 0}</span>
            </p>
          ))}
        </>
      )}
      {p.scans > 0 && (
        <p className="mt-1.5 border-t border-border/60 pt-1.5 text-muted-foreground">
          {p.scans} scan{p.scans === 1 ? "" : "s"}
          {p.gateFailed ? ` · ${p.gateFailed} gate failed` : ""}
        </p>
      )}
      {dayFixes.map((f) => (
        <p key={f.runId} className="mt-1 text-foreground">
          AI fix {f.prNumber ? `PR #${f.prNumber}` : "run"} · {f.fixed} fixed
        </p>
      ))}
    </div>
  );
}

function TrendsView() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const projectId = params.get("project") ?? "";
  const days = Number(params.get("days")) || 30;

  const [showTable, setShowTable] = useState(false);

  function setParams(values: Record<string, string | null>) {
    const next = new URLSearchParams(params.toString());
    for (const [key, value] of Object.entries(values)) {
      if (value) next.set(key, value);
      else next.delete(key);
    }
    router.replace(`${pathname}?${next.toString()}`, { scroll: false });
  }
  const setParam = (key: string, value: string | null) => setParams({ [key]: value });

  function compareWith(scanId: string) {
    const scans = repo?.scans ?? [];
    const latest = scans.find((x) => x.comparable && x.scanId !== scanId);
    if (!latest) return;
    setParams({ base: scanId, target: latest.scanId });
    document.getElementById("compare")?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  const qs = new URLSearchParams({ days: String(days) });
  if (projectId) qs.set("project", projectId);
  const { data, error: swrError, isLoading: loading } = useSWR<TrendsResponse>(
    `/api/dashboard/trends?${qs}`,
    jsonFetcher,
    { keepPreviousData: true },
  );
  const error = swrError instanceof Error ? swrError.message : null;

  const repo = data?.repo ?? null;
  const series = useMemo(
    () =>
      (data?.series ?? []).map((d) => ({
        ...d,
        total: d.critical === null ? null : sum(d as Pick<Totals, Sev>),
      })),
    [data],
  );
  const fixesByDay = useMemo(() => {
    const m = new Map<string, FixImpact[]>();
    for (const f of data?.repo?.remediations ?? []) {
      if (!f.prUrl) continue;
      const key = f.openedAt.slice(0, 10);
      m.set(key, [...(m.get(key) ?? []), f]);
    }
    return m;
  }, [data]);

  const baseline = data?.comparison.baseline ?? null;
  const current = data?.comparison.current ?? null;
  const baselineLabel = data?.comparison.baselineLabel ?? "window_start";
  const tableRows = series.filter((d) => d.scans > 0).slice().reverse();
  const projectName = repo?.project.name;

  return (
    <div className={`space-y-10 ${VIZ_VARS}`}>
      <PageBreadcrumb items={[{ label: "Dashboard", href: "/dashboard" }, { label: "Trends" }]} />

      <header className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Trends</h1>
          <p className="text-sm text-muted-foreground">
            {projectName
              ? `How ${projectName} has changed over time, including the impact of AI fixes.`
              : "Severity and build-gate trends across every repository in this organization."}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Select value={projectId || "all"} onValueChange={(v) => setParams({ project: v === "all" ? null : v, base: null, target: null })}>
            <SelectTrigger className="h-9 w-60" aria-label="Repository">
              <SelectValue placeholder="All repositories" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All repositories</SelectItem>
              {(data?.projects ?? []).map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={String(days)} onValueChange={(v) => setParam("days", v === "30" ? null : v)}>
            <SelectTrigger className="h-9 w-36" aria-label="Time range">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7">Last 7 days</SelectItem>
              <SelectItem value="30">Last 30 days</SelectItem>
              <SelectItem value="90">Last 90 days</SelectItem>
              <SelectItem value="180">Last 180 days</SelectItem>
              <SelectItem value="365">Last year</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </header>

      {error && <p className="rounded-xl bg-red-500/5 px-5 py-4 text-sm text-red-700 dark:text-red-300">{error}</p>}

      {/* Headline: before vs now */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
          <p className="text-5xl font-semibold tracking-tight tabular-nums">
            {loading && !data ? "—" : current ? sum(current) : 0}
          </p>
          <div className="space-y-0.5">
            <p className="text-sm text-foreground">
              {repo ? "findings on the latest scan" : "findings on the latest scans, across all repositories"}
            </p>
            {baseline && current && baseline.at !== current.at ? (
              <p className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                <Delta from={sum(baseline)} to={sum(current)} />
                <span>
                  vs {sum(baseline)}{" "}
                  {baselineLabel === "before_first_fix" ? "before the first AI fix" : "at the start of this range"}{" "}
                  ({fmtDate(baseline.at)})
                </span>
              </p>
            ) : (
              <p className="text-xs text-muted-foreground">
                {!data ? "\u00a0" : current ? "No earlier scan in this range to compare with." : "No scans yet."}
              </p>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {SEVERITIES.map((s) => {
            const now = current?.[s.key] ?? 0;
            const was = baseline?.[s.key];
            return (
              <div key={s.key} className="rounded-xl border border-border/70 bg-card px-4 pb-2 pt-4">
                <p className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                  <span className="h-2 w-2 rounded-full" style={{ background: s.dot }} aria-hidden />
                  {s.label}
                </p>
                <div className="mt-1 flex items-baseline justify-between gap-2">
                  <p className="text-2xl font-semibold tabular-nums">{data ? now : "—"}</p>
                  {was !== undefined && baseline && current && baseline.at !== current.at ? (
                    <span className="text-right text-xs text-muted-foreground">
                      was {was} · <Delta from={was} to={now} />
                    </span>
                  ) : null}
                </div>
                <div className="mt-2 h-10" aria-hidden>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={series} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
                      <Area
                        type="monotone"
                        dataKey={s.key}
                        stroke="var(--series-1)"
                        strokeWidth={1.5}
                        fill="var(--series-1)"
                        fillOpacity={0.1}
                        connectNulls={false}
                        isAnimationActive={false}
                        dot={false}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Total over time */}
      <section className="space-y-3">
        <div className="flex flex-wrap items-end justify-between gap-2">
          <div>
            <h2 className="text-base font-semibold">Findings over time</h2>
            <p className="text-xs text-muted-foreground">
              {repo
                ? "Latest full scan as of each day. Vertical markers are AI fix pull requests."
                : "Each repository's latest full scan as of each day, summed."}
            </p>
          </div>
          <button
            type="button"
            className="text-xs text-muted-foreground transition-colors hover:text-foreground"
            onClick={() => setShowTable((v) => !v)}
            aria-expanded={showTable}
          >
            {showTable ? "Hide data table" : "View as table"}
          </button>
        </div>
        <div className="rounded-xl border border-border/70 bg-card p-4">
          {loading && !data ? (
            <div className="h-72 animate-pulse rounded-lg bg-muted/40" />
          ) : (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={series} margin={{ top: 16, right: 12, bottom: 0, left: -12 }}>
                  <CartesianGrid vertical={false} stroke="var(--border)" strokeWidth={1} />
                  <XAxis
                    dataKey="date"
                    tickFormatter={fmtDay}
                    tick={AXIS_TICK}
                    tickLine={false}
                    axisLine={{ stroke: "var(--border)" }}
                    minTickGap={32}
                  />
                  <YAxis allowDecimals={false} tick={AXIS_TICK} tickLine={false} axisLine={false} width={48} />
                  <Tooltip
                    cursor={{ stroke: "var(--muted-foreground)", strokeWidth: 1 }}
                    content={<ChartTooltip fixes={fixesByDay} />}
                  />
                  {[...fixesByDay.entries()].map(([day, fixes]) => {
                    // Flip labels near the right edge inward so they are never clipped.
                    const nearRight = series.findIndex((d) => d.date === day) > series.length * 0.75;
                    return (
                      <ReferenceLine
                        key={day}
                        x={day}
                        stroke="var(--foreground)"
                        strokeOpacity={0.45}
                        strokeWidth={1}
                        label={{
                          value:
                            fixes.length > 1
                              ? `${fixes.length} AI fixes`
                              : fixes[0].prNumber
                                ? `AI fix #${fixes[0].prNumber}`
                                : "AI fix",
                          position: nearRight ? "insideTopRight" : "insideTopLeft",
                          fontSize: 11,
                          fill: "var(--muted-foreground)",
                        }}
                      />
                    );
                  })}
                  <Area
                    type="stepAfter"
                    dataKey="total"
                    name="Findings"
                    stroke="var(--series-1)"
                    strokeWidth={2}
                    fill="var(--series-1)"
                    fillOpacity={0.1}
                    connectNulls={false}
                    activeDot={{ r: 4, stroke: "var(--card)", strokeWidth: 2 }}
                    dot={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
          {showTable && (
            <div className="mt-4 max-h-72 overflow-auto border-t border-border/60 pt-3">
              <table className="w-full text-left text-xs">
                <thead className="text-muted-foreground">
                  <tr>
                    <th className="py-1.5 pr-4 font-medium">Date</th>
                    <th className="py-1.5 pr-4 text-right font-medium">Total</th>
                    {SEVERITIES.map((s) => (
                      <th key={s.key} className="py-1.5 pr-4 text-right font-medium">{s.label}</th>
                    ))}
                    <th className="py-1.5 text-right font-medium">Scans</th>
                  </tr>
                </thead>
                <tbody className="tabular-nums">
                  {tableRows.map((d) => (
                    <tr key={d.date} className="border-t border-border/40">
                      <td className="py-1.5 pr-4">{fmtDay(d.date)}</td>
                      <td className="py-1.5 pr-4 text-right font-medium">{d.total ?? "—"}</td>
                      {SEVERITIES.map((s) => (
                        <td key={s.key} className="py-1.5 pr-4 text-right">{d[s.key] ?? "—"}</td>
                      ))}
                      <td className="py-1.5 text-right">{d.scans}</td>
                    </tr>
                  ))}
                  {tableRows.length === 0 && (
                    <tr>
                      <td colSpan={7} className="py-3 text-muted-foreground">No scans in this range.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {/* AI fix impact (repo only) */}
      {repo && (
        <section className="space-y-3">
          <div>
            <h2 className="text-base font-semibold">AI fixes</h2>
            <p className="text-xs text-muted-foreground">
              Repository state on the last full scan before each run, and on the first full scan after it.
            </p>
          </div>
          <div className="overflow-x-auto rounded-xl border border-border/70 bg-card">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border/60 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Date</th>
                  <th className="px-4 py-2.5 font-medium">Pull request</th>
                  <th className="px-4 py-2.5 text-right font-medium">Fixed</th>
                  <th className="px-4 py-2.5 text-right font-medium">Before</th>
                  <th className="px-4 py-2.5 text-right font-medium">After</th>
                  <th className="px-4 py-2.5 font-medium">Change</th>
                </tr>
              </thead>
              <tbody>
                {repo.remediations.map((f) => (
                  <tr key={f.runId} className="border-b border-border/40 last:border-b-0">
                    <td className="px-4 py-3 text-muted-foreground">{fmtDate(f.openedAt)}</td>
                    <td className="px-4 py-3">
                      {f.prUrl ? (
                        <a
                          href={f.prUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 hover:underline"
                        >
                          {f.prNumber ? `#${f.prNumber}` : "Open PR"}
                          <ExternalLink className="h-3 w-3 text-muted-foreground" aria-hidden />
                        </a>
                      ) : (
                        <span className="text-muted-foreground">No PR</span>
                      )}
                      <Link href={`/remediation/${f.runId}`} className="ml-3 text-xs text-muted-foreground hover:text-foreground">
                        View run
                      </Link>
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums">
                      {f.fixed}
                      {f.failed ? <span className="text-muted-foreground"> / {f.fixed + f.failed}</span> : null}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums">{f.before ? sum(f.before) : "—"}</td>
                    <td className="px-4 py-3 text-right tabular-nums">{f.after ? sum(f.after) : "—"}</td>
                    <td className="px-4 py-3">
                      {f.before && f.after ? (
                        <Delta from={sum(f.before)} to={sum(f.after)} />
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          {f.prUrl ? "Awaiting a rescan after merge" : "—"}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
                {repo.remediations.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-6 text-center text-sm text-muted-foreground">
                      No AI remediation runs in this range. Select findings on a scan and choose AI Remediate.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Compare two scan versions (repo) */}
      {repo && (
        <section id="compare" className="scroll-mt-6 space-y-3">
          <div>
            <h2 className="text-base font-semibold">Compare scan versions</h2>
            <p className="text-xs text-muted-foreground">
              What was fixed, what is new and what is still present between two scans. The older scan is the baseline.
            </p>
          </div>
          <ScanCompare
            projectId={repo.project.id}
            scans={repo.scans}
            baseId={params.get("base")}
            targetId={params.get("target")}
            onChange={(base, target) => setParams({ base, target })}
          />
        </section>
      )}

      {/* Scan history (repo) / gate trend (org) */}
      {repo ? (
        <section className="space-y-3">
          <h2 className="text-base font-semibold">Scan history</h2>
          <div className="overflow-x-auto rounded-xl border border-border/70 bg-card">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border/60 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Completed</th>
                  <th className="px-4 py-2.5 font-medium">Type</th>
                  <th className="px-4 py-2.5 font-medium">Commit</th>
                  {SEVERITIES.map((s) => (
                    <th key={s.key} className="px-4 py-2.5 text-right font-medium">{s.label}</th>
                  ))}
                  <th className="px-4 py-2.5 font-medium">Gate</th>
                  <th className="px-4 py-2.5">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody className="tabular-nums">
                {repo.scans.map((s) => (
                  <tr key={s.scanId} className="border-b border-border/40 last:border-b-0">
                    <td className="px-4 py-2.5 text-muted-foreground">{fmtDate(s.completedAt)}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">
                      {s.scanType.replace("_ONLY", "").replace("_", " ").toLowerCase()}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">
                      {s.commitSha ? s.commitSha.slice(0, 8) : "—"}
                    </td>
                    {SEVERITIES.map((sev) => (
                      <td key={sev.key} className="px-4 py-2.5 text-right">{s[sev.key]}</td>
                    ))}
                    <td className="px-4 py-2.5 text-xs">
                      <span className={s.gateResult === "FAILED" ? "text-red-600 dark:text-red-400" : "text-muted-foreground"}>
                        {s.gateResult === "FAILED" ? "Failed" : s.gateResult === "PASSED" ? "Passed" : "—"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right text-xs">
                      {s.comparable ? (
                        <button
                          type="button"
                          onClick={() => compareWith(s.scanId)}
                          className="text-muted-foreground transition-colors hover:text-foreground"
                        >
                          Compare
                        </button>
                      ) : (
                        <span className="text-muted-foreground/60" title="Recorded before scan comparison was available">
                          Totals only
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
                {repo.scans.length === 0 && (
                  <tr>
                    <td colSpan={9} className="px-4 py-6 text-center text-sm text-muted-foreground">
                      No scans in this range.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      ) : (
        <section className="space-y-3">
          <div>
            <h2 className="text-base font-semibold">Scans and build gate failures</h2>
            <p className="text-xs text-muted-foreground">Scans completed each day, and how many failed the build gate.</p>
          </div>
          <div className="rounded-xl border border-border/70 bg-card p-4">
            <div className="mb-2 flex gap-4 text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <span className="h-0.5 w-3 rounded bg-[var(--series-1)]" aria-hidden /> Scans
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-0.5 w-3 rounded bg-[var(--gate)]" aria-hidden /> Gate failed
              </span>
            </div>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={series} margin={{ top: 8, right: 12, bottom: 0, left: -12 }}>
                  <CartesianGrid vertical={false} stroke="var(--border)" strokeWidth={1} />
                  <XAxis dataKey="date" tickFormatter={fmtDay} tick={AXIS_TICK} tickLine={false} axisLine={{ stroke: "var(--border)" }} minTickGap={32} />
                  <YAxis allowDecimals={false} tick={AXIS_TICK} tickLine={false} axisLine={false} width={48} />
                  <Tooltip
                    cursor={{ stroke: "var(--muted-foreground)", strokeWidth: 1 }}
                    labelFormatter={(l) => fmtDay(String(l))}
                    contentStyle={{
                      background: "var(--popover)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Line type="monotone" dataKey="scans" name="Scans" stroke="var(--series-1)" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="gateFailed" name="Gate failed" stroke="var(--gate)" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>
      )}

      {/* Mean time to resolve */}
      <section className="space-y-3">
        <div>
          <h2 className="text-base font-semibold">Mean time to resolve</h2>
          <p className="text-xs text-muted-foreground">How long findings stay open before they are marked resolved.</p>
        </div>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev, i) => {
            const v = data?.mttr[sev];
            return (
              <div key={sev} className="rounded-xl border border-border/70 bg-card px-4 py-4">
                <p className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                  <span className="h-2 w-2 rounded-full" style={{ background: SEVERITIES[i].dot }} aria-hidden />
                  {SEVERITIES[i].label}
                </p>
                <p className="mt-1 text-2xl font-semibold tabular-nums">
                  {v ? `${v.meanHours.toFixed(1)}h` : "—"}
                </p>
                <p className="text-xs text-muted-foreground">{v ? `${v.count} resolved` : "No data"}</p>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

export default function TrendsPage() {
  return (
    <Suspense fallback={null}>
      <TrendsView />
    </Suspense>
  );
}
