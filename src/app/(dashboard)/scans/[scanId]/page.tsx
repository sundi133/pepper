"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import { useScanPolling, useFindings } from "@/hooks/use-scan-polling";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ScanStatusBadge,
  GateResultBadge,
} from "@/components/scans/scan-status-badge";
import {
  LiveScanTimeline,
  isScannerProgressKey,
} from "@/components/scans/live-scan-timeline";
import { FindingsTable } from "@/components/scans/findings-table";
import { Progress } from "@/components/ui/progress";
import {
  Download,
  Ban,
  FileJson,
  FileText,
  AlertTriangle,
  BookOpen,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { useRouter } from "next/navigation";
import type { ScanEvent } from "@/scanners/types";

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const router = useRouter();
  const { scan, isLoading } = useScanPolling(scanId);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [scannerFilter, setScannerFilter] = useState<string>("all");
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(
    null,
  );
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const filters: Record<string, string> = {};
  if (severityFilter !== "all") filters.severity = severityFilter;
  if (scannerFilter !== "all") filters.scanner = scannerFilter;

  const { findings, refresh: refreshFindings } = useFindings(
    scanId,
    filters,
    scan?.status,
  );

  if (isLoading) {
    return (
      <p className="text-muted-foreground text-center py-12">Loading scan...</p>
    );
  }
  if (!scan) {
    return <p className="text-destructive text-center py-12">Scan not found</p>;
  }

  const isRunning = scan.status === "QUEUED" || scan.status === "RUNNING";
  const totalFindings =
    scan.criticalCount +
    scan.highCount +
    scan.mediumCount +
    scan.lowCount +
    scan.infoCount;

  async function handleCancel() {
    try {
      const res = await fetch(`/api/scans/${scanId}/cancel`, {
        method: "POST",
      });
      if (!res.ok) throw new Error("Failed to cancel");
      toast.success("Scan cancelled");
    } catch {
      toast.error("Failed to cancel scan");
    }
  }

  async function handleDeleteScan() {
    setDeleting(true);
    try {
      const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
      if (!res.ok) {
        const err = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(err.error || "Failed to delete scan");
      }
      toast.success("Scan deleted");
      setDeleteOpen(false);
      router.push(
        scan.projectId ? `/projects/${scan.projectId}` : "/scans",
      );
      router.refresh();
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to delete scan",
      );
    } finally {
      setDeleting(false);
    }
  }

  function downloadArtifact(type: string) {
    window.open(`/api/scans/${scanId}/artifacts/${type}`, "_blank");
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 space-y-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold">
              {scan.project?.name || "Scan"} - {scan.scanType}
            </h1>
            <ScanStatusBadge status={scan.status} />
            {scan.status === "COMPLETED" && (
              <GateResultBadge result={scan.gateResult} />
            )}
          </div>
          <p className="text-sm text-muted-foreground">
            {scan.sourceType === "SVN_CHECKOUT" && scan.sourceRef && (
              <>SVN: {scan.sourceRef}</>
            )}
            {scan.sourceType === "SVN_CHECKOUT" &&
              scan.commitSha &&
              ` | Rev: ${scan.commitSha}`}
            {scan.sourceType !== "SVN_CHECKOUT" &&
              scan.branch &&
              `Branch: ${scan.branch}`}
            {scan.sourceType !== "SVN_CHECKOUT" &&
              scan.commitSha &&
              ` | Commit: ${scan.commitSha.substring(0, 8)}`}
            {` | Created: ${new Date(scan.createdAt).toLocaleString()}`}
            {scan.completedAt &&
              ` | Duration: ${getDuration(scan.startedAt, scan.completedAt)}`}
          </p>
        </div>
        <div className="flex flex-shrink-0 flex-wrap items-center gap-2 lg:justify-end">
          {isRunning && (
            <Button variant="outline" onClick={handleCancel}>
              <Ban className="mr-2 h-4 w-4" />
              Cancel
            </Button>
          )}
          {scan.status === "COMPLETED" && (
            <>
              <Button
                variant="default"
                onClick={() => downloadArtifact("html")}
              >
                <ShieldCheck className="mr-2 h-4 w-4" />
                HTML Report
              </Button>
              <Button
                variant="outline"
                onClick={() => downloadArtifact("markdown")}
              >
                <FileText className="mr-2 h-4 w-4" />
                Markdown Report
              </Button>
              <Button
                variant="outline"
                onClick={() =>
                  window.open(
                    `/api/scans/${scanId}/findings/export?format=csv`,
                    "_blank",
                  )
                }
              >
                <Download className="mr-2 h-4 w-4" />
                Findings CSV
              </Button>
              <Button
                variant="outline"
                onClick={() =>
                  window.open(
                    `/api/scans/${scanId}/findings/export?format=json`,
                    "_blank",
                  )
                }
              >
                <Download className="mr-2 h-4 w-4" />
                Report JSON
              </Button>
              <Button
                variant="outline"
                onClick={() => downloadArtifact("sarif")}
              >
                <FileJson className="mr-2 h-4 w-4" />
                SARIF
              </Button>
              <Button
                variant="outline"
                onClick={() => downloadArtifact("sbom")}
              >
                <FileText className="mr-2 h-4 w-4" />
                SBOM
              </Button>
              <Button
                onClick={() => router.push(`/scans/${scanId}/compliance`)}
              >
                <BookOpen className="mr-2 h-4 w-4" />
                Compliance Report
              </Button>
            </>
          )}
          <Button
            type="button"
            variant="outline"
            className="border-destructive/50 text-destructive hover:bg-destructive/10"
            onClick={() => setDeleteOpen(true)}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Delete scan
          </Button>
        </div>
      </div>

      <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete this scan?</DialogTitle>
            <DialogDescription>
              All findings and artifacts for this scan will be permanently
              removed. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setDeleteOpen(false)}
              disabled={deleting}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              onClick={handleDeleteScan}
              disabled={deleting}
            >
              {deleting ? "Deleting…" : "Delete scan"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Progress bar for running scans */}
      {isRunning && (
        <Card>
          <CardContent className="py-6">
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span>Scanning...</span>
                <span className="text-muted-foreground">{scan.status}</span>
              </div>
              <LiveScanTimeline
                events={
                  (
                    scan.scannerProgress as {
                      liveScan?: { events?: ScanEvent[]; seq?: number };
                    } | null
                  )?.liveScan?.events
                }
                isRunning={isRunning}
              />
              <Progress
                value={computeScanProgress(scan.scannerProgress, scan.status)}
              />
              {scan.scannerProgress &&
                Object.keys(scan.scannerProgress).length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {Object.entries(
                      scan.scannerProgress as Record<
                        string,
                        {
                          status: string;
                          findingsCount: number;
                          filesCompleted?: number;
                          filesTotal?: number;
                        }
                      >,
                    )
                      .filter(([name]) => isScannerProgressKey(name))
                      .map(([name, info]) => (
                      <Badge
                        key={name}
                        variant={
                          info.status === "DONE" ? "default" : "secondary"
                        }
                      >
                        {name}:{" "}
                        {info.status === "DONE"
                          ? `Done (${info.findingsCount})`
                          : info.filesTotal
                            ? `${info.filesCompleted}/${info.filesTotal} files (${info.findingsCount} findings)`
                            : `Running (${info.findingsCount} so far)`}
                      </Badge>
                    ))}
                  </div>
                )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Summary Cards */}
      {(scan.status === "COMPLETED" || scan.status === "RUNNING") && (
        <div className="grid gap-4 md:grid-cols-5">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-red-600" />
                <span className="text-sm text-muted-foreground">Critical</span>
              </div>
              <p className="text-2xl font-bold mt-1">{scan.criticalCount}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-orange-500" />
                <span className="text-sm text-muted-foreground">High</span>
              </div>
              <p className="text-2xl font-bold mt-1">{scan.highCount}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-yellow-500" />
                <span className="text-sm text-muted-foreground">Medium</span>
              </div>
              <p className="text-2xl font-bold mt-1">{scan.mediumCount}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-blue-400" />
                <span className="text-sm text-muted-foreground">Low</span>
              </div>
              <p className="text-2xl font-bold mt-1">{scan.lowCount}</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-gray-400" />
                <span className="text-sm text-muted-foreground">Info</span>
              </div>
              <p className="text-2xl font-bold mt-1">{scan.infoCount}</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Findings */}
      {(scan.status === "COMPLETED" || scan.status === "RUNNING") && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>
                Findings ({totalFindings})
                {scan.status === "RUNNING" && (
                  <span className="text-sm font-normal text-muted-foreground ml-2">
                    (partial — scan in progress)
                  </span>
                )}
              </CardTitle>
              <div className="flex gap-2">
                <Select
                  value={severityFilter}
                  onValueChange={setSeverityFilter}
                >
                  <SelectTrigger className="w-36">
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Severities</SelectItem>
                    <SelectItem value="CRITICAL">Critical</SelectItem>
                    <SelectItem value="HIGH">High</SelectItem>
                    <SelectItem value="MEDIUM">Medium</SelectItem>
                    <SelectItem value="LOW">Low</SelectItem>
                    <SelectItem value="INFO">Info</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={scannerFilter} onValueChange={setScannerFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Scanner" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Scanners</SelectItem>
                    <SelectItem value="SAST_PATTERN">SAST (Pattern)</SelectItem>
                    <SelectItem value="SAST_LLM">SAST (AI)</SelectItem>
                    <SelectItem value="SCA">SCA</SelectItem>
                    <SelectItem value="SECRETS_PATTERN">
                      Secrets (Pattern)
                    </SelectItem>
                    <SelectItem value="SECRETS_LLM">Secrets (AI)</SelectItem>
                    <SelectItem value="IAC">IaC Security</SelectItem>
                    <SelectItem value="MALICIOUS_PKG">Supply Chain</SelectItem>
                    <SelectItem value="ZERO_DAY">Zero-Day (AI)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <FindingsTable
              findings={findings}
              expandedId={expandedFindingId}
              onExpandedChange={setExpandedFindingId}
              onBulkStatusChange={() => refreshFindings()}
            />
          </CardContent>
        </Card>
      )}

      {/* Error message */}
      {scan.status === "FAILED" && scan.errorMessage && (
        <Card>
          <CardContent className="py-6">
            <div className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-5 w-5" />
              <span className="font-medium">Scan Failed</span>
            </div>
            <p className="text-sm text-muted-foreground mt-2">
              {scan.errorMessage}
            </p>
          </CardContent>
        </Card>
      )}

    </div>
  );
}

function computeScanProgress(
  scannerProgress:
    | Record<
        string,
        { status: string; filesCompleted?: number; filesTotal?: number }
      >
    | null
    | undefined,
  status: string,
): number {
  if (status === "QUEUED") return 5;
  if (!scannerProgress || Object.keys(scannerProgress).length === 0) return 10;

  const entries = Object.entries(scannerProgress)
    .filter(([k]) => isScannerProgressKey(k))
    .map(([, v]) => v);
  const done = entries.filter((s) => s.status === "DONE").length;
  const total = Math.max(entries.length + 1, 3);

  // If any scanner has file-level progress, use it for finer granularity
  let fileProgress = 0;
  let hasFileProgress = false;
  for (const s of entries) {
    if (s.status === "DONE") {
      fileProgress += 1;
    } else if (s.filesTotal && s.filesTotal > 0) {
      hasFileProgress = true;
      fileProgress += (s.filesCompleted || 0) / s.filesTotal;
    }
  }

  if (hasFileProgress) {
    // Weighted: file-level progress across all known scanners
    return Math.min(95, Math.round(10 + (fileProgress / total) * 85));
  }

  // Fallback: count done scanners
  return Math.min(95, Math.round(10 + (done / total) * 85));
}

function getDuration(start: string, end: string): string {
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}
