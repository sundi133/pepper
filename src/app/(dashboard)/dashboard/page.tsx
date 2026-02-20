"use client";

import { useScans, useProjects } from "@/hooks/use-scan-polling";
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

export default function DashboardPage() {
  const { scans, isLoading: scansLoading } = useScans();
  const { projects } = useProjects();

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
