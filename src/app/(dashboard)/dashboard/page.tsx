"use client";

import { useMemo, type ComponentType, type ReactNode } from "react";
import { useSession } from "next-auth/react";
import { useProjects } from "@/hooks/use-scan-polling";
import useSWR from "swr";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  AlertTriangle,
  KeyRound,
  Package,
  Zap,
  Users,
  FolderKanban,
  CheckCircle2,
} from "lucide-react";
import Link from "next/link";
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend } from "recharts";

const fetcher = (url: string) => fetch(url).then((r) => r.json());

type DashboardOverview = {
  projectCount: number;
  memberCount: number;
  monitoredSchedules: number;
  secretsFindingCount: number;
  dependencyFindingCount: number;
  resolvedThisMonth: number;
  lastScanAt: string | null;
  lastScanStatus: string | null;
  recentProjects: Array<{
    id: string;
    name: string;
    updatedAt: string;
    lastScanAt: string | null;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
  }>;
  activities: Array<{
    id: string;
    status: string;
    scanType: string;
    createdAt: string;
    projectName: string;
  }>;
};

type DashboardStats = {
  severity?: { name: string; count: number }[];
  overview?: DashboardOverview;
  owasp?: { category: string; count: number }[];
};

const SEVERITY_ORDER = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
] as const;

const SEVERITY_HEX: Record<string, string> = {
  CRITICAL: "#d32f2f",
  HIGH: "#f57c00",
  MEDIUM: "#fbc02d",
  LOW: "#1976d2",
  INFO: "#00796b",
};

const SCAN_STATUS_USER: Record<string, string> = {
  QUEUED: "queued",
  RUNNING: "started",
  PAUSED: "paused",
  COMPLETED: "completed",
  FAILED: "failed",
  CANCELLED: "cancelled",
  STOPPED: "stopped",
};

function greetingName(raw: string | null | undefined) {
  if (!raw) return "there";
  const first = raw.trim().split(/\s+/)[0];
  return first.length > 24 ? `${first.slice(0, 24)}…` : first;
}

function timeOfDayGreeting() {
  const h = new Date().getHours();
  if (h < 12) return "Good morning";
  if (h < 18) return "Good afternoon";
  return "Good evening";
}

function formatRelative(iso: string | null): string {
  if (!iso) return "Never";
  const t = Date.now() - new Date(iso).getTime();
  const s = Math.floor(t / 1000);
  if (s < 45) return "Just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 7) return `${Math.floor(s / 86400)}d ago`;
  return new Date(iso).toLocaleDateString();
}

function buildSeverityChart(
  rows: { name: string; count: number }[] | undefined,
) {
  const map = new Map<string, number>();
  for (const k of SEVERITY_ORDER) map.set(k, 0);
  for (const r of rows || []) {
    map.set(r.name, (map.get(r.name) || 0) + r.count);
  }
  return SEVERITY_ORDER.map((name) => ({
    name,
    count: map.get(name) || 0,
  }));
}

function totalFindings(chart: { count: number }[]) {
  return chart.reduce((a, b) => a + b.count, 0);
}

function activityDescription(a: {
  status: string;
  scanType: string;
  projectName: string;
}) {
  const verb = SCAN_STATUS_USER[a.status] || "updated";
  const type = a.scanType.replace(/_/g, " ").toLowerCase();
  if (a.status === "RUNNING" || a.status === "QUEUED") {
    return `Security scan ${verb} for ${a.projectName} (${type})`;
  }
  if (a.status === "COMPLETED") {
    return `Scan ${verb} for ${a.projectName}`;
  }
  return `Scan ${verb} for ${a.projectName} (${type})`;
}

export default function DashboardPage() {
  const { data: session } = useSession();
  const { projects } = useProjects();
  const { data: stats } = useSWR<DashboardStats>(
    "/api/dashboard/stats",
    fetcher,
    { refreshInterval: 30000 },
  );

  const overview = stats?.overview;

  const severityChart = useMemo(
    () => buildSeverityChart(stats?.severity),
    [stats?.severity],
  );

  const vulnTotal = totalFindings(severityChart);
  const criticalCount =
    severityChart.find((s) => s.name === "CRITICAL")?.count ?? 0;

  const displayName = greetingName(session?.user?.name || session?.user?.email);
  const orgName =
    session?.user?.memberships?.[0]?.organizationName || "your organization";

  const pieData = severityChart.filter((s) => s.count > 0);
  const pieFallback =
    pieData.length === 0 ? [{ name: "INFO", count: 1, _empty: true }] : pieData;

  return (
    <div className="mx-auto w-full max-w-7xl space-y-5 pb-6 sm:space-y-6">
      {/* Hero */}
      <section className="flex flex-col gap-3 sm:gap-4 lg:flex-row lg:items-start lg:justify-between lg:gap-6">
        <div className="min-w-0 space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
            {timeOfDayGreeting()}, {displayName}{" "}
            <span className="inline-block" aria-hidden>
              👋
            </span>
          </h1>
          <p className="text-sm text-muted-foreground sm:text-base">
            Here&apos;s your security overview for{" "}
            <span className="font-medium text-foreground/90">{orgName}</span>.
          </p>
        </div>
        <div className="flex w-full flex-col gap-2 sm:max-w-md sm:flex-row sm:flex-wrap sm:items-center lg:w-auto lg:max-w-none lg:shrink-0">
        </div>
      </section>


      {/* Metrics */}
      <section aria-label="Summary metrics">
        <div className="grid grid-cols-2 gap-2.5 sm:gap-3 md:grid-cols-3 lg:grid-cols-6">
          <MetricTile
            label="Total projects"
            value={overview?.projectCount ?? projects.length}
            icon={FolderKanban}
          />
          <MetricTile
            label="Vulnerabilities"
            value={vulnTotal}
            sub={
              criticalCount > 0 ? (
                <span className="text-destructive">{criticalCount} critical</span>
              ) : (
                <span className="text-muted-foreground">No critical</span>
              )
            }
            icon={AlertTriangle}
            iconClassName="text-destructive"
          />
          <MetricTile
            label="Secrets exposed"
            value={overview?.secretsFindingCount ?? 0}
            icon={KeyRound}
          />
          <MetricTile
            label="Dependency issues"
            value={overview?.dependencyFindingCount ?? 0}
            icon={Package}
          />
          <MetricTile
            label="Monitored repos"
            value={overview?.monitoredSchedules ?? 0}
            icon={Zap}
          />
          <MetricTile
            label="Team members"
            value={overview?.memberCount ?? 0}
            icon={Users}
          />
        </div>
      </section>

      {/* Severity + monitoring */}
      <section className="grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-stretch">
        <Card className="flex min-h-0 flex-col border-border/60 bg-card/80">
          <CardHeader className="space-y-1 pb-2 sm:pb-4">
            <CardTitle className="text-lg sm:text-xl">
              Vulnerabilities by severity
            </CardTitle>
            <CardDescription className="text-xs sm:text-sm">
              All findings in your organization
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-1 flex-col gap-4 pt-0 md:flex-row md:items-center md:gap-6">
            <div className="relative mx-auto h-[220px] w-[220px] shrink-0 md:mx-0">
              <ResponsiveContainer width={220} height={220}>
                <PieChart>
                  <Pie
                    data={pieFallback}
                    dataKey="count"
                    nameKey="name"
                    cx={110}
                    cy={110}
                    innerRadius={62}
                    outerRadius={88}
                    paddingAngle={2}
                    stroke="none"
                  >
                    {pieFallback.map((entry, i) => (
                      <Cell
                        key={i}
                        fill={
                          (entry as { _empty?: boolean })._empty
                            ? "#e5e5e5"
                            : SEVERITY_HEX[entry.name] || "#999999"
                        }
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#ffffff",
                      border: "1px solid #e0e0e0",
                      borderRadius: "8px",
                      fontSize: "12px",
                      color: "#1a1a1a",
                      boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center pt-1">
                <span className="text-2xl font-bold tabular-nums text-foreground sm:text-3xl">
                  {vulnTotal}
                </span>
                <span className="text-xs text-muted-foreground">total</span>
              </div>
            </div>
            <ul className="min-w-0 flex-1 space-y-2 sm:space-y-2.5">
              {severityChart.map((s) => {
                const pct =
                  vulnTotal > 0 ? Math.round((s.count / vulnTotal) * 100) : 0;
                return (
                  <li
                    key={s.name}
                    className="flex items-center justify-between gap-2 text-sm"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span
                        className="h-2.5 w-2.5 shrink-0 rounded-full"
                        style={{ backgroundColor: SEVERITY_HEX[s.name] }}
                      />
                      <span className="capitalize text-muted-foreground">
                        {s.name.toLowerCase()}
                      </span>
                    </span>
                    <span className="shrink-0 tabular-nums text-foreground">
                      {s.count}{" "}
                      <span className="text-muted-foreground">({pct}%)</span>
                    </span>
                  </li>
                );
              })}
            </ul>
          </CardContent>
        </Card>

        <Card className="flex min-h-0 flex-col border-border/60 bg-card/80">
          <CardHeader className="space-y-1">
            <CardTitle className="text-lg sm:text-xl">Top vulnerabilities by type</CardTitle>
            <CardDescription className="text-xs sm:text-sm">
              Vulnerability breakdown by severity level
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-1 flex-col">
            {severityChart.filter((s) => s.count > 0).length === 0 ? (
              <div className="flex flex-1 flex-col justify-center rounded-lg bg-muted/15 px-3 py-6 text-center sm:py-8">
                <p className="text-sm text-muted-foreground">
                  No vulnerabilities detected
                </p>
              </div>
            ) : (
              <ul className="space-y-3">
                {severityChart
                  .filter((s) => s.count > 0)
                  .map((s) => {
                    const pct =
                      vulnTotal > 0 ? Math.round((s.count / vulnTotal) * 100) : 0;
                    return (
                      <li key={s.name} className="space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="flex items-center gap-2 text-sm font-medium">
                            <span
                              className="h-2.5 w-2.5 shrink-0 rounded-full"
                              style={{
                                backgroundColor: SEVERITY_HEX[s.name],
                              }}
                            />
                            <span className="capitalize text-foreground">
                              {s.name.toLowerCase()}
                            </span>
                          </span>
                          <span className="text-sm font-semibold text-foreground">
                            {s.count}
                          </span>
                        </div>
                        <div className="h-2 overflow-hidden rounded-full bg-muted/30">
                          <div
                            className="h-full rounded-full transition-all"
                            style={{
                              width: `${pct}%`,
                              backgroundColor: SEVERITY_HEX[s.name],
                            }}
                          />
                        </div>
                      </li>
                    );
                  })}
              </ul>
            )}
          </CardContent>
        </Card>
      </section>

      {/* Top Vulnerabilities Distribution */}
      <section aria-label="Top Vulnerabilities">
        <Card className="flex min-h-0 flex-col border-border/60 bg-card/80">
          <CardHeader className="space-y-1 pb-2 sm:pb-3">
            <CardTitle className="text-base sm:text-lg">Top 10 Vulnerabilities</CardTitle>
            <CardDescription className="text-xs sm:text-sm">
              Most common findings across all scans
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-1 flex-col pt-0">
            {(!stats?.owasp || stats.owasp.length === 0) ? (
              <div className="flex flex-1 flex-col justify-center rounded-lg bg-muted/15 px-3 py-4 text-center sm:py-6">
                <p className="text-xs sm:text-sm text-muted-foreground">
                  No findings yet
                </p>
              </div>
            ) : (
              <div className="h-48 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={stats.owasp}
                    margin={{ top: 10, right: 15, left: 0, bottom: 60 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#e0e0e0" vertical={false} />
                    <XAxis
                      dataKey="category"
                      angle={-45}
                      textAnchor="end"
                      height={70}
                      tick={{ fontSize: 9, fill: "#666666" }}
                      interval={0}
                    />
                    <YAxis
                      tick={{ fontSize: 10, fill: "#666666" }}
                      width={25}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#ffffff",
                        border: "1px solid #e0e0e0",
                        borderRadius: "4px",
                        fontSize: "10px",
                        color: "#1a1a1a",
                        boxShadow: "0 2px 6px rgba(0,0,0,0.08)",
                      }}
                      formatter={(value) => value}
                      labelFormatter={(label) => `${label}`}
                    />
                    <Bar
                      dataKey="count"
                      fill="#ff8c42"
                      radius={[4, 4, 0, 0]}
                      name="Findings"
                    />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>
      </section>

      {/* Projects + activity */}
      <section className="grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-stretch">
        <Card className="flex min-h-0 flex-col border-border/60 bg-card/80">
          <CardHeader className="flex flex-col gap-3 space-y-0 pb-2 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
            <div className="min-w-0 space-y-1">
              <CardTitle className="text-lg sm:text-xl">Recent projects</CardTitle>
              <CardDescription className="text-xs sm:text-sm">
                Latest in your workspace
              </CardDescription>
            </div>
            <Link
              href="/projects"
              className="shrink-0 text-sm font-medium text-primary hover:underline sm:pt-1"
            >
              View all
            </Link>
          </CardHeader>
          <CardContent className="min-h-0 flex-1 space-y-1">
            {(overview?.recentProjects?.length ?? 0) === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No projects yet. Create a project to start scanning.
              </p>
            ) : (
              overview?.recentProjects?.map((p) => (
                <Link
                  key={p.id}
                  href={`/projects/${p.id}`}
                  className="flex flex-col gap-2 rounded-lg px-2 py-2.5 transition-colors hover:bg-muted/20 sm:flex-row sm:items-center sm:justify-between sm:px-3"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                      <FolderKanban className="h-4 w-4" />
                    </div>
                    <div className="min-w-0">
                      <p className="truncate font-medium text-foreground">
                        {p.name}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {formatRelative(p.lastScanAt ?? p.updatedAt)}
                      </p>
                    </div>
                  </div>
                  <div className="shrink-0 pl-12 sm:pl-0">
                    <SeverityBadges
                      c={p.criticalCount}
                      h={p.highCount}
                      m={p.mediumCount}
                      l={p.lowCount}
                    />
                  </div>
                </Link>
              ))
            )}
          </CardContent>
        </Card>

        <Card className="flex min-h-0 flex-col border-border/60 bg-card/80">
          <CardHeader className="space-y-1">
            <CardTitle className="text-lg sm:text-xl">Activity feed</CardTitle>
            <CardDescription className="text-xs sm:text-sm">
              Recent activity
            </CardDescription>
          </CardHeader>
          <CardContent className="min-h-0 flex-1">
            {(overview?.activities?.length ?? 0) === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No activity yet. Start a scan to populate this feed.
              </p>
            ) : (
              <ul className="relative max-h-[min(28rem,65vh)] overflow-y-auto overflow-x-hidden pr-1 sm:max-h-[32rem]">
                {overview?.activities?.map((a) => (
                  <li
                    key={a.id}
                    className="flex gap-3 border-b border-border/40 py-3 first:pt-0 last:border-0 last:pb-0"
                  >
                    <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-primary/15 text-primary">
                      <CheckCircle2 className="h-3 w-3" />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="break-words text-sm text-foreground">
                        {activityDescription(a)}
                      </p>
                      <p className="mt-0.5 text-xs text-muted-foreground">
                        {formatRelative(a.createdAt)}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

function MetricTile({
  label,
  value,
  sub,
  icon: Icon,
  iconClassName,
}: {
  label: string;
  value: number;
  sub?: ReactNode;
  icon: ComponentType<{ className?: string }>;
  iconClassName?: string;
}) {
  return (
    <Card className="border-border/60 bg-card/80 shadow-sm">
      <CardContent className="flex items-start justify-between gap-2 p-3.5 sm:gap-3 sm:p-4">
        <div className="min-w-0 flex-1 space-y-1">
          <p className="text-[10px] font-medium uppercase leading-tight tracking-wide text-muted-foreground sm:text-xs">
            {label}
          </p>
          <p className="text-xl font-bold tabular-nums text-foreground sm:text-2xl">
            {value}
          </p>
          {sub ? <p className="text-[11px] leading-tight sm:text-xs">{sub}</p> : null}
        </div>
        <div
          className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary/10 sm:h-10 sm:w-10 ${iconClassName ?? "text-primary"}`}
        >
          <Icon className="h-4 w-4 sm:h-5 sm:w-5" />
        </div>
      </CardContent>
    </Card>
  );
}

function SeverityBadges({
  c,
  h,
  m,
  l,
}: {
  c: number;
  h: number;
  m: number;
  l: number;
}) {
  if (c + h + m + l === 0) {
    return (
      <span className="text-xs text-muted-foreground">No completed scan</span>
    );
  }
  return (
    <div className="flex flex-wrap gap-1">
      {c > 0 && (
        <span className="rounded px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-white bg-[#d32f2f]">
          {c}
        </span>
      )}
      {h > 0 && (
        <span className="rounded px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-white bg-[#f57c00]">
          {h}
        </span>
      )}
      {m > 0 && (
        <span className="rounded px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-black bg-[#fbc02d]">
          {m}
        </span>
      )}
      {l > 0 && (
        <span className="rounded px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-white bg-[#1976d2]">
          {l}
        </span>
      )}
    </div>
  );
}
