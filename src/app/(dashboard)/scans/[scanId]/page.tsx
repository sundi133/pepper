"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";
import { useScanPolling, useFindings } from "@/hooks/use-scan-polling";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";
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
  FileText,
  AlertTriangle,
  BookOpen,
  RotateCcw,
  Trash2,
  Pause,
  Play,
  Check,
} from "lucide-react";
import { toast } from "sonner";
import { mutate } from "swr";
import { useRouter } from "next/navigation";
import { nextFindingSelection } from "@/lib/create-scan-validation";
import { runOpenFixPrFlow } from "@/lib/open-fix-pr-flow";

/** Stronger scan toolbar outline buttons (readable while a scan is running). */
const scanToolbarOutlineClass =
  "font-semibold text-foreground shadow-sm border-2 border-border bg-background hover:bg-muted/80 dark:border-border/80 dark:hover:bg-muted/50";

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
    scanners: ["SAST_LLM", "SAST_PATTERN"],
    description: "Static application security findings (AI and pattern-based)",
  },
  {
    id: "SECRETS",
    title: "Secrets Findings",
    scanners: ["SECRETS_LLM", "SECRETS_PATTERN"],
    description: "Leaked or exposed credential findings (AI and pattern-based)",
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
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const filters: Record<string, string> = {};
  if (severityFilter !== "all") filters.severity = severityFilter;
  if (scannerFilter !== "all") filters.scanner = scannerFilter;

  const { findings, refresh: refreshFindings } = useFindings(
    scanId,
    filters,
    scan?.status,
  );

  useEffect(() => {
    if (
      typeof window === "undefined" ||
      window.location.hash !== "#scan-findings"
    ) {
      return;
    }
    const el = document.getElementById("scan-findings");
    if (!el) return;
    const t = window.setTimeout(() => {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 150);
    return () => window.clearTimeout(t);
  }, [scanId, scan?.status, findings]);

  useEffect(() => {
    if (typeof window === "undefined" || isLoading || !scan) return;
    const params = new URLSearchParams(window.location.search);
    if (params.get("github") !== "connected") return;
    const openPrFindingId = params.get("openPr");
    if (!openPrFindingId) return;

    const resumeKey = `openPr:${scanId}:${openPrFindingId}`;
    if (sessionStorage.getItem(resumeKey)) return;
    sessionStorage.setItem(resumeKey, "1");

    router.replace(`/scans/${scanId}`, { scroll: false });

    void (async () => {
      toast.message("GitHub connected — opening fix pull request…");
      const outcome = await runOpenFixPrFlow(scanId, openPrFindingId, {
        skipConfirm: true,
      });
      if ("redirected" in outcome) return;
      if (!outcome.ok) {
        toast.error(outcome.error);
        return;
      }
      toast.success("Pull request opened");
      window.open(outcome.pullRequestUrl, "_blank", "noopener,noreferrer");
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once after OAuth return
  }, [scanId, isLoading, scan, router]);

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageBreadcrumb
          items={[
            { label: "Dashboard", href: "/dashboard" },
            { label: "Projects", href: "/projects" },
            { label: "Scan" },
          ]}
        />
        <p className="text-muted-foreground text-center py-12">
          Loading scan...
        </p>
      </div>
    );
  }
  if (!scan) {
    return (
      <div className="space-y-6">
        <PageBreadcrumb
          items={[
            { label: "Dashboard", href: "/dashboard" },
            { label: "Projects", href: "/projects" },
            { label: "Scan not found" },
          ]}
        />
        <p className="text-destructive text-center py-12">Scan not found</p>
      </div>
    );
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
  const visibleFindings = findings as Finding[];
  const visibleFindingCount =
    visibleFindings.length === totalFindings
      ? String(visibleFindings.length)
      : `${visibleFindings.length} of ${totalFindings}`;
  const findingSections = groupFindingsBySection(visibleFindings);

  const fixPrSource = {
    scanId: scan.id,
    sourceType: scan.sourceType,
    repoUrl: scan.project?.repoUrl ?? null,
    scanSourceRef: scan.sourceRef ?? null,
    defaultBranch: scan.project?.defaultBranch ?? "main",
    branch: scan.branch ?? null,
    commitSha: scan.commitSha ?? null,
  };

  const project = scan.project as
    | { id?: string; name?: string }
    | null
    | undefined;
  const projectIdForCrumb = project?.id ?? (scan as { projectId?: string }).projectId;
  const breadcrumbItems = [
    { label: "Dashboard", href: "/dashboard" },
    { label: "Projects", href: "/projects" },
    ...(project?.name && projectIdForCrumb
      ? [{ label: project.name, href: `/projects/${projectIdForCrumb}` }]
      : []),
    {
      label: `${scan.scanType} scan`,
    },
  ];

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

  async function handleRescan() {
    setRescanning(true);
    try {
      const res = await fetch(`/api/scans/${scanId}/rescan`, {
        method: "POST",
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || "Failed to start rescan");
      toast.success("Rescan queued");
      await Promise.all([
        mutate("/api/notifications?summary=unread"),
        mutate("/api/notifications"),
      ]);
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

  return (
    <div className="space-y-6">
      <PageBreadcrumb items={breadcrumbItems} />

      {/* Header */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="space-y-1 min-w-0">
          <div className="flex min-w-0 flex-wrap items-center gap-2 sm:gap-3">
            <h1 className="text-xl font-bold break-words sm:text-2xl">
              {scan.project?.name || "Scan"} - {scan.scanType}
            </h1>
            <ScanStatusBadge status={scan.status} />
            {scan.status === "COMPLETED" && (
              <GateResultBadge result={scan.gateResult} />
            )}
          </div>
          <p className="text-sm text-muted-foreground">
            {formatScanMetadataLine(scan)}
          </p>
        </div>
        <div className="flex flex-wrap gap-2 shrink-0">
          <Button
            variant="destructive"
            className="font-semibold shadow-sm"
            disabled={deleting || isRunning || isPaused}
            onClick={handleDelete}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
          <Button
            variant="outline"
            className={scanToolbarOutlineClass}
            disabled={rescanning}
            onClick={handleRescan}
          >
            <RotateCcw className="mr-2 h-4 w-4" />
            Rescan
          </Button>
          {isRunning && (
            <Button
              variant="outline"
              className={scanToolbarOutlineClass}
              disabled={pausing}
              onClick={handlePause}
            >
              <Pause className="mr-2 h-4 w-4" />
              {pausing ? "Pausing..." : "Pause"}
            </Button>
          )}
          {(isPaused || isStopped) && (
            <Button
              variant="outline"
              className={scanToolbarOutlineClass}
              disabled={resuming}
              onClick={handleResume}
            >
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
              className={scanToolbarOutlineClass}
              onClick={handleCancel}
            >
              <Ban className="mr-2 h-4 w-4" />
              Cancel
            </Button>
          )}
          {hasReportableFindings && (
            <>
              <Button
                variant="outline"
                className={scanToolbarOutlineClass}
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
                className={scanToolbarOutlineClass}
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
                <Button
                  variant="default"
                  className="font-semibold shadow-sm"
                  onClick={() => router.push(`/scans/${scanId}/compliance`)}
                >
                  <BookOpen className="mr-2 h-4 w-4" />
                  Compliance Report
                </Button>
              )}
              {scan.status === "COMPLETED" && (
                <>
                  <Button
                    variant="outline"
                    className={scanToolbarOutlineClass}
                    onClick={() =>
                      window.open(
                        `/api/scans/${scanId}/artifacts/cyclonedx`,
                        "_blank",
                      )
                    }
                  >
                    <Download className="mr-2 h-4 w-4" />
                    SBOM (CycloneDX)
                  </Button>
                  <Button
                    variant="outline"
                    className={scanToolbarOutlineClass}
                    onClick={() =>
                      window.open(
                        `/api/scans/${scanId}/artifacts/spdx`,
                        "_blank",
                      )
                    }
                  >
                    <Download className="mr-2 h-4 w-4" />
                    SBOM (SPDX)
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
                        className="gap-1.5 font-medium"
                      >
                        {info.status === "DONE" ? (
                          <>
                            <Check
                              className="h-3.5 w-3.5 shrink-0"
                              aria-hidden
                            />
                            <span>{name}</span>
                            <span className="opacity-90">Done</span>
                          </>
                        ) : (
                          <span>{name}: Running</span>
                        )}
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
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5 lg:gap-4">
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
        <Card
          id="scan-findings"
          tabIndex={-1}
          className="scroll-mt-24 outline-none ring-offset-background focus-visible:ring-2 focus-visible:ring-ring"
        >
          <CardHeader>
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between sm:gap-3">
              <CardTitle>Findings ({visibleFindingCount})</CardTitle>
              <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:flex-wrap">
                <Select
                  value={severityFilter}
                  onValueChange={setSeverityFilter}
                >
                  <SelectTrigger className="w-full sm:w-36">
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
                  <SelectTrigger className="w-full sm:w-40">
                    <SelectValue placeholder="Scanner" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Scanners</SelectItem>
                    <SelectItem value="SAST_LLM">SAST (AI)</SelectItem>
                    <SelectItem value="SAST_PATTERN">SAST (Pattern)</SelectItem>
                    <SelectItem value="SCA">SCA</SelectItem>
                    <SelectItem value="SECRETS_LLM">Secrets (AI)</SelectItem>
                    <SelectItem value="SECRETS_PATTERN">
                      Secrets (Pattern)
                    </SelectItem>
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
                fixPrSource={fixPrSource}
                onSelect={(f) =>
                  setSelectedFinding((prev) => nextFindingSelection(prev, f))
                }
                selectedId={selectedFinding?.id as string}
                onBulkStatusChange={() => refreshFindings()}
                renderExpanded={(finding) => (
                  <FindingDetailInline
                    finding={finding}
                    sourceContext={
                      scan
                        ? {
                            scanId: scan.id,
                            sourceType: scan.sourceType,
                            repoUrl: scan.project?.repoUrl ?? null,
                            scanSourceRef: scan.sourceRef ?? null,
                            defaultBranch: scan.project?.defaultBranch ?? "main",
                            branch: scan.branch ?? null,
                            commitSha: scan.commitSha ?? null,
                          }
                        : undefined
                    }
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
                      fixPrSource={fixPrSource}
                      onSelect={(f) =>
                        setSelectedFinding((prev) =>
                          nextFindingSelection(prev, f),
                        )
                      }
                      selectedId={selectedFinding?.id as string}
                      onBulkStatusChange={() => refreshFindings()}
                      renderExpanded={(finding) => (
                        <FindingDetailInline
                          finding={finding}
                          sourceContext={
                            scan
                              ? {
                                  scanId: scan.id,
                                  sourceType: scan.sourceType,
                                  repoUrl: scan.project?.repoUrl ?? null,
                                  scanSourceRef: scan.sourceRef ?? null,
                                  defaultBranch:
                                    scan.project?.defaultBranch ?? "main",
                                  branch: scan.branch ?? null,
                                  commitSha: scan.commitSha ?? null,
                                }
                              : undefined
                          }
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

      {/* Error / stop details */}
      {scan.errorMessage &&
        (scan.status === "FAILED" || scan.status === "CANCELLED") && (
        <Card className="border-destructive/40 bg-destructive/5">
          <CardContent className="space-y-3 py-6">
            <div className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-5 w-5 shrink-0" aria-hidden />
              <span className="text-base font-semibold">
                {scan.status === "FAILED"
                  ? "Scan failed"
                  : "Scan cancelled"}
              </span>
            </div>
            <p className="text-base leading-relaxed text-foreground whitespace-pre-wrap break-words">
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

function formatScanMetadataLine(scan: {
  sourceType: string;
  sourceRef?: string | null;
  branch?: string | null;
  commitSha?: string | null;
  createdAt: string;
}): string {
  const parts: string[] = [];
  if (scan.sourceType === "SVN_CHECKOUT") {
    if (scan.sourceRef) parts.push(`SVN: ${scan.sourceRef}`);
    if (scan.commitSha) parts.push(`Rev: ${scan.commitSha}`);
  } else {
    if (scan.branch) parts.push(`Branch: ${scan.branch}`);
    if (scan.commitSha)
      parts.push(`Commit: ${scan.commitSha.substring(0, 8)}`);
  }
  parts.push(`Created: ${new Date(scan.createdAt).toLocaleString()}`);
  return parts.join(" · ");
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
