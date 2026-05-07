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
import { CreateScanForm } from "@/components/scans/create-scan-dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import Link from "next/link";
import { RotateCcw, Trash2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { useRouter } from "next/navigation";

const ARCHIVE_EXTENSION_REGEX = /\.(tar\.gz|zip|tgz|tar)$/i;

function getScanSourceName(scan: Record<string, unknown>) {
  const sourceRef = scan.sourceRef as string | undefined;
  const sourceType = scan.sourceType as string | undefined;
  const scanId = scan.id as string;

  if (!sourceRef) return `${scanId.slice(0, 8)}...`;

  if (sourceType === "UPLOAD") {
    const fileName = sourceRef.split("/").pop() || sourceRef;
    const sourceName = fileName.replace(ARCHIVE_EXTENSION_REGEX, "");
    return sourceName === "source" ? `${scanId.slice(0, 8)}...` : sourceName;
  }

  try {
    const url = new URL(sourceRef);
    return (url.pathname.split("/").filter(Boolean).pop() || sourceRef).replace(
      /\.git$/i,
      "",
    );
  } catch {
    return (sourceRef.split(/[\\/]/).pop() || sourceRef).replace(/\.git$/i, "");
  }
}

export default function ScansPage() {
  const { scans, isLoading, refresh } = useScans();
  const { projects } = useProjects();
  const router = useRouter();
  const [rescanningId, setRescanningId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  async function handleRescan(scanId: string) {
    setRescanningId(scanId);
    try {
      const res = await fetch(`/api/scans/${scanId}/rescan`, {
        method: "POST",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to start rescan");
      toast.success("Rescan queued");
      router.push(`/scans/${data.scanId}`);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to start rescan",
      );
      setRescanningId(null);
    }
  }

  async function handleDeleteScan(scanId: string) {
    if (!confirm("Delete this scan and all of its findings?")) return;

    setDeletingId(scanId);
    try {
      const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to delete scan");
      toast.success("Scan deleted");
      refresh();
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to delete scan",
      );
    } finally {
      setDeletingId(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scans</h1>
          <p className="text-muted-foreground">All scan activity</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Start a New Scan</CardTitle>
          <CardDescription>
            Upload source code or provide a repository URL to scan for
            vulnerabilities.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <CreateScanForm projects={projects} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>All Scans</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <p className="text-muted-foreground text-center py-8">Loading...</p>
          ) : scans.length === 0 ? (
            <p className="text-muted-foreground text-center py-8">
              No scans yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Source</TableHead>
                  <TableHead>Project</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Branch</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Critical/High</TableHead>
                  <TableHead>Total</TableHead>
                  <TableHead>Gate</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan: Record<string, unknown>) => (
                  <TableRow key={scan.id as string}>
                    <TableCell className="max-w-48">
                      <Link
                        href={`/scans/${scan.id}`}
                        className="font-medium hover:underline"
                        title={scan.sourceRef as string | undefined}
                      >
                        {getScanSourceName(scan)}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Link
                        href={`/scans/${scan.id}`}
                        className="font-medium hover:underline"
                      >
                        {(scan.project as { name: string })?.name || "Unknown"}
                      </Link>
                    </TableCell>
                    <TableCell className="text-sm">
                      {scan.scanType as string}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {(scan.branch as string) || "-"}
                    </TableCell>
                    <TableCell>
                      <ScanStatusBadge status={scan.status as string} />
                    </TableCell>
                    <TableCell>
                      {scan.status === "COMPLETED" && (
                        <span className="text-sm font-medium text-destructive">
                          {(scan.criticalCount as number) +
                            (scan.highCount as number)}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      {scan.status === "COMPLETED" && (
                        <span className="text-sm">
                          {(scan.criticalCount as number) +
                            (scan.highCount as number) +
                            (scan.mediumCount as number) +
                            (scan.lowCount as number) +
                            (scan.infoCount as number)}
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
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={rescanningId === scan.id}
                          onClick={() => handleRescan(scan.id as string)}
                        >
                          <RotateCcw className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={
                            deletingId === scan.id ||
                            scan.status === "RUNNING" ||
                            scan.status === "PAUSED"
                          }
                          onClick={() => handleDeleteScan(scan.id as string)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
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
