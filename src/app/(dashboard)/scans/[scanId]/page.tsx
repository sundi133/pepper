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
import { FindingsTable } from "@/components/scans/findings-table";
import { FindingDetailInline } from "@/components/scans/finding-detail-panel";
import { Progress } from "@/components/ui/progress";
import {
  Download,
  Ban,
  FileJson,
  FileText,
  AlertTriangle,
  BookOpen,
  RotateCcw,
  Trash2,
  Pause,
  Play,
  Square,
} from "lucide-react";
import { toast } from "sonner";
import { useRouter } from "next/navigation";

type Finding = {
  id: string;
  scanner: string;
  severity: string;
  title: string;
  description: string;
  status?: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  snippet?: string;
  ruleId?: string;
  cweId?: string;
  cveId?: string;
  confidence?: number;
  metadata?: Record<string, unknown>;
};

const FINDING_SECTIONS = [
  {
    id: "SAST",
    title: "SAST Findings",
    scanners: ["SAST_LLM"],
    description: "LLM-based static code analysis findings",
  },
  {
    id: "SECRETS",
    title: "Secrets Findings",
    scanners: ["SECRETS_LLM"],
    description: "LLM-confirmed leaked credential findings",
  },
  {
    id: "SCA",
    title: "SCA Findings",
    scanners: ["SCA"],
    description: "Known vulnerable dependency findings",
  },
  {
    id: "MALICIOUS_PKG",
    title: "Supply Chain Findings",
    scanners: ["MALICIOUS_PKG"],
    description: "Malicious package, typosquat, and install-script findings",
  },
  {
    id: "IAC",
    title: "IaC Findings",
    scanners: ["IAC"],
    description: "Infrastructure, cloud, container, and CI/CD findings",
  },
  {
    id: "ZERO_DAY",
    title: "Zero-Day Findings",
    scanners: ["ZERO_DAY"],
    description: "Business logic, IDOR, race, and advanced AI findings",
  },
];

export default function ScanDetailPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const router = useRouter();
  const { scan, isLoading } = useScanPolling(scanId);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [scannerFilter, setScannerFilter] = useState<string>("all");
  const [rescanning, setRescanning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [pausing, setPausing] = useState(false);
  const [resuming, setResuming] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

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

  const isRunning = scan.status === "RUNNING";
  const isPaused = scan.status === "PAUSED";
  const isStopped = scan.status === "STOPPED";
  const isActive =
    scan.status === "QUEUED" || scan.status === "RUNNING" || isPaused;
  const hasReportableFindings =
    scan.status === "COMPLETED" || scan.status === "STOPPED";
  const totalFindings =
    scan.criticalCount +
    scan.highCount +
    scan.mediumCount +
    scan.lowCount +
    scan.infoCount;
  const visibleFindings = (findings as Finding[]).filter(
    (finding) =>
      finding.scanner !== "SAST_PATTERN" &&
      finding.scanner !== "SECRETS_PATTERN",
  );
  const visibleFindingCount =
    visibleFindings.length === totalFindings
      ? String(visibleFindings.length)
      : `${visibleFindings.length} of ${totalFindings}`;
  const findingSections = groupFindingsBySection(visibleFindings);

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

  async function handlePause() {
    setPausing(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/pause`, {
        method: "POST",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to pause scan");
      toast.success("Scan paused");
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to pause scan",
      );
    } finally {
      setPausing(false);
    }
  }

  async function handleResume() {
    setResuming(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/resume`, {
        method: "POST",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to resume scan");
      toast.success(isStopped ? "Scan restarted" : "Scan resumed");
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to resume scan",
      );
    } finally {
      setResuming(false);
    }
  }

  async function handleStopAndReport() {
    if (
      !confirm(
        "Stop this scan and generate an HTML report from findings collected so far? Stopped scans can only be restarted from the beginning. Use Pause if you want to continue from the same point.",
      )
    )
      return;

    setStopping(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/stop`, {
        method: "POST",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to stop scan");
      toast.success("Scan stopped. Opening partial HTML report...");
      window.open(
        data.reportUrl || `/api/scans/${scanId}/findings/export?format=html`,
        "_blank",
      );
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to stop scan",
      );
    } finally {
      setStopping(false);
    }
  }

  async function handleRescan() {
    setRescanning(true);
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
      setRescanning(false);
    }
  }

  async function handleDelete() {
    if (!confirm("Delete this scan and all of its findings?")) return;

    setDeleting(true);
    try {
      const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to delete scan");
      toast.success("Scan deleted");
      router.push("/scans");
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to delete scan",
      );
      setDeleting(false);
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
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={deleting || isRunning || isPaused}
            onClick={handleDelete}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
          <Button variant="outline" disabled={rescanning} onClick={handleRescan}>
            <RotateCcw className="mr-2 h-4 w-4" />
            Rescan
          </Button>
          {isRunning && (
            <Button variant="outline" disabled={pausing} onClick={handlePause}>
              <Pause className="mr-2 h-4 w-4" />
              {pausing ? "Pausing..." : "Pause"}
            </Button>
          )}
          {(isPaused || isStopped) && (
            <Button variant="outline" disabled={resuming} onClick={handleResume}>
              <Play className="mr-2 h-4 w-4" />
              {resuming
                ? isStopped
                  ? "Restarting..."
                  : "Resuming..."
                : isStopped
                  ? "Restart Scan"
                  : "Resume"}
            </Button>
          )}
          {isActive && (
            <Button
              variant="outline"
              disabled={stopping}
              onClick={handleStopAndReport}
            >
              <Square className="mr-2 h-4 w-4" />
              {stopping ? "Stopping..." : "Stop & Report"}
            </Button>
          )}
          {isActive && (
            <Button variant="outline" onClick={handleCancel}>
              <Ban className="mr-2 h-4 w-4" />
              Cancel
            </Button>
          )}
          {hasReportableFindings && (
            <>
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
                Findings JSON
              </Button>
              <Button
                variant="outline"
                onClick={() =>
                  window.open(
                    `/api/scans/${scanId}/findings/export?format=html`,
                    "_blank",
                  )
                }
              >
                <FileText className="mr-2 h-4 w-4" />
                HTML Report
              </Button>
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
                  <Button
                    onClick={() => router.push(`/scans/${scanId}/compliance`)}
                  >
                    <BookOpen className="mr-2 h-4 w-4" />
                    Compliance Report
                  </Button>
                </>
              )}
            </>
          )}
        </div>
      </div>

      {/* Progress bar for active scans */}
      {isActive && (
        <Card>
          <CardContent className="py-6">
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span>{isPaused ? "Scan paused" : "Scanning..."}</span>
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
                        {
                          status: string;
                          findingsCount: number;
                          filesCompleted?: number;
                          filesTotal?: number;
                        }
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
      {(hasReportableFindings || isActive) && (
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
      {(hasReportableFindings || isActive) && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>
                Findings ({visibleFindingCount})
                {(isActive || scan.status === "STOPPED") && (
                  <span className="text-sm font-normal text-muted-foreground ml-2">
                    {scan.status === "STOPPED"
                      ? "(partial — scan stopped)"
                      : isPaused
                      ? "(partial — scan paused)"
                      : "(partial — scan in progress)"}
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
                    <SelectItem value="SAST_LLM">SAST (AI)</SelectItem>
                    <SelectItem value="SCA">SCA</SelectItem>
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
            {findingSections.length === 0 ? (
              <FindingsTable
                findings={visibleFindings}
                onSelect={(f) => setSelectedFinding(f)}
                selectedId={selectedFinding?.id as string}
                onBulkStatusChange={() => refreshFindings()}
                renderExpanded={(finding) => (
                  <FindingDetailInline
                    finding={finding}
                    onClose={() => setSelectedFinding(null)}
                    onStatusChange={() => refreshFindings()}
                  />
                )}
              />
            ) : (
              <div className="space-y-6">
                {findingSections.map((section) => (
                  <div key={section.id} className="space-y-3">
                    <div className="flex items-center justify-between border-b pb-2">
                      <div>
                        <h3 className="font-semibold">{section.title}</h3>
                        <p className="text-sm text-muted-foreground">
                          {section.description}
                        </p>
                      </div>
                      <Badge variant="outline">
                        {section.findings.length} findings
                      </Badge>
                    </div>
                    <FindingsTable
                      findings={section.findings}
                      onSelect={(f) => setSelectedFinding(f)}
                      selectedId={selectedFinding?.id as string}
                      onBulkStatusChange={() => refreshFindings()}
                      renderExpanded={(finding) => (
                        <FindingDetailInline
                          finding={finding}
                          onClose={() => setSelectedFinding(null)}
                          onStatusChange={() => refreshFindings()}
                        />
                      )}
                    />
                  </div>
                ))}
              </div>
            )}
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

  const entries = Object.values(scannerProgress);
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

function groupFindingsBySection(findings: Finding[]) {
  const groupedScannerNames = new Set(
    FINDING_SECTIONS.flatMap((section) => section.scanners),
  );
  const sections = FINDING_SECTIONS.map((section) => ({
    ...section,
    findings: findings.filter((finding) =>
      section.scanners.includes(finding.scanner),
    ),
  })).filter((section) => section.findings.length > 0);
  const ungrouped = findings.filter(
    (finding) => !groupedScannerNames.has(finding.scanner),
  );

  if (ungrouped.length > 0) {
    sections.push({
      id: "OTHER",
      title: "Other Findings",
      scanners: [],
      description: "Findings from scanners that do not have a dedicated group",
      findings: ungrouped,
    });
  }

  return sections;
}
