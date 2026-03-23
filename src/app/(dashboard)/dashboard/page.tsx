"use client";

import { useScans, useProjects } from "@/hooks/use-scan-polling";
import useSWR from "swr";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  ScanStatusBadge,
  GateResultBadge,
} from "@/components/scans/scan-status-badge";
import { CreateScanDialog } from "@/components/scans/create-scan-dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Shield, Scan, AlertTriangle, CheckCircle2 } from "lucide-react";
import Link from "next/link";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend,
} from "recharts";
import { SCANNER_LABELS } from "@/lib/constants";

const fetcher = (url: string) => fetch(url).then((r) => r.json());

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#2563eb",
  INFO: "#6b7280",
};

export default function DashboardPage() {
  const { scans, isLoading: scansLoading } = useScans();
  const { projects } = useProjects();
  const { data: stats } = useSWR("/api/dashboard/stats", fetcher, {
    refreshInterval: 30000,
  });

  const completedScans = scans.filter(
    (s: { status: string }) => s.status === "COMPLETED",
  );
  const totalFindings = completedScans.reduce(
    (
      acc: number,
      s: {
        criticalCount: number;
        highCount: number;
        mediumCount: number;
        lowCount: number;
      },
    ) => acc + s.criticalCount + s.highCount + s.mediumCount + s.lowCount,
    0,
  );
  const criticalHighCount = completedScans.reduce(
    (acc: number, s: { criticalCount: number; highCount: number }) =>
      acc + s.criticalCount + s.highCount,
    0,
  );
  const passedGates = completedScans.filter(
    (s: { gateResult: string }) => s.gateResult === "PASSED",
  ).length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground">
            Overview of your security scan results
          </p>
        </div>
        <CreateScanDialog projects={projects} />
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Scan className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{scans.length}</div>
            <p className="text-xs text-muted-foreground">
              {completedScans.length} completed
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">
              Total Findings
            </CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalFindings}</div>
            <p className="text-xs text-muted-foreground">
              Across all completed scans
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">
              Critical + High
            </CardTitle>
            <AlertTriangle className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">
              {criticalHighCount}
            </div>
            <p className="text-xs text-muted-foreground">
              Require immediate attention
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">
              Gate Pass Rate
            </CardTitle>
            <CheckCircle2 className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {completedScans.length > 0
                ? `${Math.round((passedGates / completedScans.length) * 100)}%`
                : "N/A"}
            </div>
            <p className="text-xs text-muted-foreground">
              {passedGates} of {completedScans.length} passed
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      {stats && (
        <div className="grid gap-4 md:grid-cols-2">
          {/* Findings Trend */}
          {stats.trend?.length > 0 && (
            <Card className="md:col-span-2">
              <CardHeader>
                <CardTitle>Findings Trend</CardTitle>
                <CardDescription>
                  Severity breakdown across recent scans
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={stats.trend}>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      className="stroke-muted"
                    />
                    <XAxis
                      dataKey="date"
                      className="text-xs"
                      tick={{ fontSize: 11 }}
                    />
                    <YAxis className="text-xs" tick={{ fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "hsl(var(--card))",
                        border: "1px solid hsl(var(--border))",
                        borderRadius: "8px",
                        fontSize: "12px",
                      }}
                    />
                    <Legend />
                    <Area
                      type="monotone"
                      dataKey="critical"
                      stackId="1"
                      stroke="#dc2626"
                      fill="#dc2626"
                      fillOpacity={0.6}
                    />
                    <Area
                      type="monotone"
                      dataKey="high"
                      stackId="1"
                      stroke="#ea580c"
                      fill="#ea580c"
                      fillOpacity={0.5}
                    />
                    <Area
                      type="monotone"
                      dataKey="medium"
                      stackId="1"
                      stroke="#ca8a04"
                      fill="#ca8a04"
                      fillOpacity={0.4}
                    />
                    <Area
                      type="monotone"
                      dataKey="low"
                      stackId="1"
                      stroke="#2563eb"
                      fill="#2563eb"
                      fillOpacity={0.3}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* Severity Breakdown Pie */}
          {stats.severity?.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Severity Breakdown</CardTitle>
                <CardDescription>
                  Finding distribution by severity
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart>
                    <Pie
                      data={stats.severity}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={2}
                      dataKey="count"
                      nameKey="name"
                      label={(props: { name?: string; value?: number }) =>
                        `${props.name} (${props.value})`
                      }
                      labelLine={false}
                    >
                      {stats.severity.map(
                        (entry: { name: string }, i: number) => (
                          <Cell
                            key={i}
                            fill={SEVERITY_COLORS[entry.name] || "#6b7280"}
                          />
                        ),
                      )}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* Scanner Distribution */}
          {stats.scanners?.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Scanner Distribution</CardTitle>
                <CardDescription>Findings by scanner type</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart
                    data={stats.scanners.map(
                      (s: { name: string; count: number }) => ({
                        ...s,
                        label:
                          SCANNER_LABELS[
                            s.name as keyof typeof SCANNER_LABELS
                          ] || s.name,
                      }),
                    )}
                    layout="vertical"
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      className="stroke-muted"
                    />
                    <XAxis type="number" tick={{ fontSize: 11 }} />
                    <YAxis
                      dataKey="label"
                      type="category"
                      width={120}
                      tick={{ fontSize: 11 }}
                    />
                    <Tooltip />
                    <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* Top Vulnerable Files */}
          {stats.topFiles?.length > 0 && (
            <Card className="md:col-span-2">
              <CardHeader>
                <CardTitle>Top Vulnerable Files</CardTitle>
                <CardDescription>Files with the most findings</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {stats.topFiles.map(
                    (f: { filePath: string; count: number }, i: number) => (
                      <div
                        key={i}
                        className="flex items-center justify-between rounded-md bg-muted/50 px-3 py-2"
                      >
                        <span className="font-mono text-sm truncate max-w-[70%]">
                          {f.filePath}
                        </span>
                        <span className="text-sm font-bold text-destructive">
                          {f.count}
                        </span>
                      </div>
                    ),
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Recent Scans */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Scans</CardTitle>
          <CardDescription>
            Latest scan activity across all projects
          </CardDescription>
        </CardHeader>
        <CardContent>
          {scansLoading ? (
            <p className="text-muted-foreground py-8 text-center">Loading...</p>
          ) : scans.length === 0 ? (
            <p className="text-muted-foreground py-8 text-center">
              No scans yet. Create your first scan to get started.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Project</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Gate</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.slice(0, 10).map((scan: Record<string, unknown>) => (
                  <TableRow key={scan.id as string}>
                    <TableCell>
                      <Link
                        href={`/scans/${scan.id}`}
                        className="font-medium hover:underline"
                      >
                        {(scan.project as { name: string })?.name || "Unknown"}
                      </Link>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {scan.scanType as string}
                    </TableCell>
                    <TableCell>
                      <ScanStatusBadge status={scan.status as string} />
                    </TableCell>
                    <TableCell>
                      {scan.status === "COMPLETED" && (
                        <span className="text-sm">
                          <span className="text-destructive font-medium">
                            {(scan.criticalCount as number) +
                              (scan.highCount as number)}
                          </span>
                          {" / "}
                          <span className="text-muted-foreground">
                            {(scan.criticalCount as number) +
                              (scan.highCount as number) +
                              (scan.mediumCount as number) +
                              (scan.lowCount as number)}
                          </span>
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {scan.status === "COMPLETED" && (
                        <GateResultBadge result={scan.gateResult as string} />
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(scan.createdAt as string).toLocaleDateString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
