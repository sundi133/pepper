"use client";

import { useScans, useProjects } from "@/hooks/use-scan-polling";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScanStatusBadge, GateResultBadge } from "@/components/scans/scan-status-badge";
import { CreateScanDialog } from "@/components/scans/create-scan-dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import Link from "next/link";

export default function ScansPage() {
  const { scans, isLoading } = useScans();
  const { projects } = useProjects();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scans</h1>
          <p className="text-muted-foreground">All scan activity</p>
        </div>
        <CreateScanDialog projects={projects} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Scans</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground text-center py-8">Loading...</p>
          ) : scans.length === 0 ? (
            <p className="text-muted-foreground text-center py-8">No scans yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Project</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Branch</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Critical/High</TableHead>
                  <TableHead>Total</TableHead>
                  <TableHead>Gate</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan: Record<string, unknown>) => (
                  <TableRow key={scan.id as string}>
                    <TableCell>
                      <Link
                        href={`/scans/${scan.id}`}
                        className="font-medium hover:underline"
                      >
                        {(scan.project as { name: string })?.name || "Unknown"}
                      </Link>
                    </TableCell>
                    <TableCell className="text-sm">{scan.scanType as string}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {(scan.branch as string) || "-"}
                    </TableCell>
                    <TableCell>
                      <ScanStatusBadge status={scan.status as string} />
                    </TableCell>
                    <TableCell>
                      {scan.status === "COMPLETED" && (
                        <span className="text-sm font-medium text-destructive">
                          {(scan.criticalCount as number) + (scan.highCount as number)}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {scan.status === "COMPLETED" && (
                        <span className="text-sm">
                          {(scan.criticalCount as number) +
                            (scan.highCount as number) +
                            (scan.mediumCount as number) +
                            (scan.lowCount as number)}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {scan.status === "COMPLETED" && (
                        <GateResultBadge result={scan.gateResult as string} />
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(scan.createdAt as string).toLocaleString()}
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
