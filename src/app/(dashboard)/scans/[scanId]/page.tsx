"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import { useScanPolling, useFindings } from "@/hooks/use-scan-polling";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
  SeverityBadge,
} from "@/components/scans/scan-status-badge";
import { FindingsTable } from "@/components/scans/findings-table";
import { FindingDetailPanel } from "@/components/scans/finding-detail-panel";
import { Progress } from "@/components/ui/progress";
import {
  Download,
  Ban,
  FileJson,
  FileText,
  AlertTriangle,
  Shield,
  Key,
} from "lucide-react";
import { toast } from "sonner";

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const { scan, isLoading } = useScanPolling(scanId);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [scannerFilter, setScannerFilter] = useState<string>("all");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [selectedFinding, setSelectedFinding] = useState<any>(null);

  const filters: Record<string, string> = {};
  if (severityFilter !== "all") filters.severity = severityFilter;
  if (scannerFilter !== "all") filters.scanner = scannerFilter;

  const { findings } = useFindings(scanId, filters, scan?.status);

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

  function downloadArtifact(type: string) {
    window.open(`/api/scans/${scanId}/artifacts/${type}`, "_blank");
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-1">
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
            {scan.branch && `Branch: ${scan.branch}`}
            {scan.commitSha && ` | Commit: ${scan.commitSha.substring(0, 8)}`}
            {` | Created: ${new Date(scan.createdAt).toLocaleString()}`}
            {scan.completedAt &&
              ` | Duration: ${getDuration(scan.startedAt, scan.completedAt)}`}
          </p>
        </div>
        <div className="flex gap-2">
          {isRunning && (
            <Button variant="outline" onClick={handleCancel}>
              <Ban className="mr-2 h-4 w-4" />
              Cancel
            </Button>
          )}
          {scan.status === "COMPLETED" && (
            <>
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
            </>
          )}
        </div>
      </div>

      {/* Progress bar for running scans */}
      {isRunning && (
        <Card>
          <CardContent className="py-6">
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span>Scanning...</span>
                <span className="text-muted-foreground">{scan.status}</span>
              </div>
              <Progress
                value={computeScanProgress(scan.scannerProgress, scan.status)}
              />
              {scan.scannerProgress &&
                Object.keys(scan.scannerProgress).length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {Object.entries(
                      scan.scannerProgress as Record<
                        string,
                        { status: string; findingsCount: number }
                      >,
                    ).map(([name, info]) => (
                      <Badge
                        key={name}
                        variant={
                          info.status === "DONE" ? "default" : "secondary"
                        }
                      >
                        {name}:{" "}
                        {info.status === "DONE"
                          ? `Done (${info.findingsCount})`
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
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <FindingsTable
              findings={findings}
              onSelect={(f) => setSelectedFinding(f)}
              selectedId={selectedFinding?.id as string}
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

      {/* Finding Detail Panel */}
      <FindingDetailPanel
        finding={
          selectedFinding as
            | (Record<string, unknown> & {
                id: string;
                scanner: string;
                severity: string;
                title: string;
                description: string;
              })
            | null
        }
        open={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}

function computeScanProgress(
  scannerProgress: Record<string, { status: string }> | null | undefined,
  status: string,
): number {
  if (status === "QUEUED") return 5;
  if (!scannerProgress || Object.keys(scannerProgress).length === 0) return 10;

  const scanners = Object.values(scannerProgress);
  const done = scanners.filter((s) => s.status === "DONE").length;
  // Assume ~5 scanners max; scale from 10-95%
  const total = Math.max(scanners.length + 1, 3); // at least expect one more
  return Math.min(95, Math.round(10 + (done / total) * 85));
}

function getDuration(start: string, end: string): string {
  const ms = new Date(end).getTime() - new Date(start).getTime();
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}
