"use client";

import { useState, useEffect, useMemo } from "react";
import { useSession } from "next-auth/react";
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
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from "@/components/ui/tabs";
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
  AlertTriangle,
  BookOpen,
  RotateCcw,
  Trash2,
  Pause,
  Play,
  Check,
  Clock,
  Timer,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { mutate } from "swr";
import { useRouter } from "next/navigation";
import { nextFindingSelection } from "@/lib/create-scan-validation";
import { runOpenFixPrFlow } from "@/lib/open-fix-pr-flow";
import { ScanTriageChat } from "@/components/scans/scan-triage-chat";

/** Stronger scan toolbar outline buttons (readable while a scan is running). */
const scanToolbarOutlineClass =
  "text-xs sm:text-sm h-9 sm:h-10 px-3 sm:px-4 text-foreground border border-border/60 bg-background hover:bg-primary/5 dark:border-border/40 dark:hover:bg-primary/10 hover:border-primary/40 dark:hover:border-primary/50 transition-colors whitespace-nowrap";

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
  riskScore?: number | null;
  isNew?: boolean | null;
  metadata?: Record<string, unknown>;
};

const FINDING_SECTIONS = [
  {
    id: "SAST",
    title: "SAST Findings",
    scanners: ["SAST_LLM"],
    description: "Static application security findings (AI)",
  },
  {
    id: "SECRETS",
    title: "Secrets Findings",
    scanners: ["SECRETS_LLM"],
    description: "Leaked or exposed credential findings (AI)",
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
    id: "CONTAINER",
    title: "Container Findings",
    scanners: ["CONTAINER"],
    description: "Docker image and container security findings",
  },
  {
    id: "ZERO_DAY",
    title: "Zero-Day Findings",
    scanners: ["ZERO_DAY"],
    description: "Business logic, IDOR, race, and advanced AI findings",
  },
];

export default function ScanDetailPage() {
  const { data: session } = useSession();
  const params = useParams();
  const scanId = params.scanId as string;
  const router = useRouter();
  const { scan, isLoading } = useScanPolling(scanId);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [scannerFilter, setScannerFilter] = useState<string>("all");
  const [newOnlyFilter, setNewOnlyFilter] = useState(false);
  const [sortBy, setSortBy] = useState<string>("severity");
  const [rescanning, setRescanning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [pausing, setPausing] = useState(false);
  const [resuming, setResuming] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [now, setNow] = useState(Date.now());
  const [activeSection, setActiveSection] = useState<string>("");

  const orgRole = session?.user?.memberships?.[0]?.role;
  const canRescan = orgRole && ["ADMIN", "SECURITY", "DEVELOPER"].includes(orgRole);
  const canDelete = orgRole && ["ADMIN", "SECURITY"].includes(orgRole);
  const canManageScan = orgRole && ["ADMIN", "SECURITY"].includes(orgRole);

  const filters: Record<string, string> = {};
  if (severityFilter !== "all") filters.severity = severityFilter;
  if (scannerFilter !== "all") filters.scanner = scannerFilter;
  if (newOnlyFilter) filters.isNew = "true";
  if (sortBy !== "severity") filters.sort = sortBy;

  const { findings, pagination, refresh: refreshFindings } = useFindings(
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

  // Auto-select first section tab when findings change
  useEffect(() => {
    const sections = groupFindingsBySection(findings as Finding[]);
    setActiveSection(sections[0]?.id ?? "");
  }, [findings]);

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
  }, [scanId, isLoading, scan, router]);

  const isRunning = scan?.status === "RUNNING";
  const isPaused = scan?.status === "PAUSED";
  const isStopped = scan?.status === "STOPPED";
  const isActive =
    scan?.status === "QUEUED" || scan?.status === "RUNNING" || isPaused;

  // Live elapsed time + ETA ticker (updates every second while active)
  useEffect(() => {
    if (!isActive) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [isActive]);

  const etaInfo = useMemo(
    () =>
      scan
        ? computeEta(scan.startedAt, scan.scannerProgress, scan.status, now)
        : null,
    [scan, now],
  );

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

  const hasReportableFindings =
    scan.status === "COMPLETED" || scan.status === "STOPPED";
  const totalFindings = pagination?.total ??
    scan.criticalCount +
    scan.highCount +
    scan.mediumCount +
    scan.lowCount +
    scan.infoCount;
  const visibleFindings = findings as Finding[];
  const visibleFindingCount =
    visibleFindings.length >= totalFindings
      ? String(totalFindings)
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
    <div className="min-w-0 max-w-full space-y-6 overflow-hidden">
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
          {canDelete && (
            <Button
              variant="destructive"
              className="text-xs sm:text-sm h-9 sm:h-10 px-3 sm:px-4 bg-red-600 hover:bg-red-700 dark:bg-red-700 dark:hover:bg-red-800 transition-colors whitespace-nowrap"
              disabled={deleting || isRunning || isPaused}
              onClick={handleDelete}
              title="Delete this scan and all findings"
            >
              <Trash2 className="mr-2 h-4 w-4" />
              <span className="hidden sm:inline">Delete</span>
              <span className="sm:hidden">Del</span>
            </Button>
          )}
          {canRescan && (
            <Button
              variant="outline"
              className={scanToolbarOutlineClass}
              disabled={rescanning}
              onClick={handleRescan}
            >
              <RotateCcw className="mr-2 h-4 w-4" />
              {rescanning ? "Rescanning..." : "Rescan"}
            </Button>
          )}
          {canManageScan && isRunning && (
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
          {canManageScan && (isPaused || isStopped) && (
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
          {canManageScan && isActive && (
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
                    `/api/scans/${scanId}/findings/export?format=pdf`,
                    "_blank",
                  )
                }
              >
                <Download className="mr-2 h-4 w-4" />
                PDF Report
              </Button>
              {scan.status === "COMPLETED" && (
                <Button
                  variant="outline"
                  className={scanToolbarOutlineClass}
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
                <span className="text-muted-foreground font-medium">
                  {etaInfo?.etaText}
                </span>
              </div>
              <Progress
                value={computeScanProgress(scan.scannerProgress, scan.status)}
              />
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                {etaInfo?.elapsedText && (
                  <span className="inline-flex items-center gap-1">
                    <Clock className="h-3 w-3" aria-hidden />
                    {etaInfo.elapsedText}
                  </span>
                )}
                {etaInfo?.fileProgressText && (
                  <span className="inline-flex items-center gap-1">
                    <Timer className="h-3 w-3" aria-hidden />
                    {etaInfo.fileProgressText}
                  </span>
                )}
              </div>
              {scan.scannerProgress &&
                Object.keys(scan.scannerProgress).length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-1">
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
                          <span>
                            {name}: Running
                            {info.filesTotal
                              ? ` (${info.filesCompleted ?? 0}/${info.filesTotal})`
                              : ""}
                          </span>
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
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5 lg:gap-3">
          <Card className="border-0 bg-gradient-to-br from-red-50 to-red-50/50 dark:from-red-950/30 dark:to-red-950/10 shadow-sm hover:shadow-md transition-shadow">
            <CardContent className="pt-4 pb-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="h-3 w-3 rounded-full bg-red-600 shadow-lg shadow-red-600/20" />
                <span className="text-xs font-semibold text-red-700 dark:text-red-400 uppercase tracking-wider">Critical</span>
              </div>
              <p className="text-3xl font-bold text-red-700 dark:text-red-400">{scan.criticalCount}</p>
              <div className="mt-1.5 h-0.5 w-10 bg-gradient-to-r from-red-600 to-red-400 rounded-full"></div>
            </CardContent>
          </Card>
          <Card className="border-0 bg-gradient-to-br from-orange-50 to-orange-50/50 dark:from-orange-950/30 dark:to-orange-950/10 shadow-sm hover:shadow-md transition-shadow">
            <CardContent className="pt-4 pb-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="h-3 w-3 rounded-full bg-orange-500 shadow-lg shadow-orange-500/20" />
                <span className="text-xs font-semibold text-orange-700 dark:text-orange-400 uppercase tracking-wider">High</span>
              </div>
              <p className="text-3xl font-bold text-orange-700 dark:text-orange-400">{scan.highCount}</p>
              <div className="mt-1.5 h-0.5 w-10 bg-gradient-to-r from-orange-500 to-orange-400 rounded-full"></div>
            </CardContent>
          </Card>
          <Card className="border-0 bg-gradient-to-br from-yellow-50 to-yellow-50/50 dark:from-yellow-950/30 dark:to-yellow-950/10 shadow-sm hover:shadow-md transition-shadow">
            <CardContent className="pt-4 pb-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="h-3 w-3 rounded-full bg-yellow-500 shadow-lg shadow-yellow-500/20" />
                <span className="text-xs font-semibold text-yellow-700 dark:text-yellow-400 uppercase tracking-wider">Medium</span>
              </div>
              <p className="text-3xl font-bold text-yellow-700 dark:text-yellow-400">{scan.mediumCount}</p>
              <div className="mt-1.5 h-0.5 w-10 bg-gradient-to-r from-yellow-500 to-yellow-400 rounded-full"></div>
            </CardContent>
          </Card>
          <Card className="border-0 bg-gradient-to-br from-blue-50 to-blue-50/50 dark:from-blue-950/30 dark:to-blue-950/10 shadow-sm hover:shadow-md transition-shadow">
            <CardContent className="pt-4 pb-4">
              <div className="flex items-center gap-2 mb-2">
                <div className="h-3 w-3 rounded-full bg-blue-500 shadow-lg shadow-blue-500/20" />
                <span className="text-xs font-semibold text-blue-700 dark:text-blue-400 uppercase tracking-wider">Low</span>
              </div>
              <p className="text-3xl font-bold text-blue-700 dark:text-blue-400">{scan.lowCount}</p>
              <div className="mt-1.5 h-0.5 w-10 bg-gradient-to-r from-blue-500 to-blue-400 rounded-full"></div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Auto-resolved banner */}
      {scan.status === "COMPLETED" && (scan as { autoResolvedCount?: number }).autoResolvedCount ? (
        <div className="flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-2.5 text-sm text-emerald-800 dark:border-emerald-800 dark:bg-emerald-950/30 dark:text-emerald-300">
          <Check className="h-4 w-4 shrink-0" />
          <span>
            <span className="font-semibold">{(scan as { autoResolvedCount?: number }).autoResolvedCount}</span>
            {" "}previously-open{" "}
            {(scan as { autoResolvedCount?: number }).autoResolvedCount === 1 ? "finding was" : "findings were"}{" "}
            auto-resolved — no longer detected in this scan.
          </span>
        </div>
      ) : null}

      {/* Findings */}
      {(hasReportableFindings || isActive) && (
        <div
          id="scan-findings"
          tabIndex={-1}
          className="scroll-mt-24 outline-none ring-offset-background focus-visible:ring-2 focus-visible:ring-ring min-w-0 w-full"
        >
          <div className="space-y-6">
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between sm:gap-3">
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-2xl font-bold">Findings ({visibleFindingCount})</h2>
                {scan.status === "COMPLETED" && (scan as { newFindingCount?: number }).newFindingCount ? (
                  <button
                    type="button"
                    onClick={() => setNewOnlyFilter((v) => !v)}
                    className={cn(
                      "inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors",
                      newOnlyFilter
                        ? "bg-blue-600 text-white"
                        : "bg-blue-100 text-blue-800 hover:bg-blue-200 dark:bg-blue-900/40 dark:text-blue-300",
                    )}
                  >
                    {(scan as { newFindingCount?: number }).newFindingCount} new
                  </button>
                ) : null}
              </div>
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
                    <SelectItem value="SCA">SCA</SelectItem>
                    <SelectItem value="SECRETS_LLM">Secrets (AI)</SelectItem>
                    <SelectItem value="IAC">IaC Security</SelectItem>
                    <SelectItem value="MALICIOUS_PKG">Supply Chain</SelectItem>
                    <SelectItem value="CONTAINER">Container</SelectItem>
                    <SelectItem value="ZERO_DAY">Zero-Day (AI)</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={sortBy} onValueChange={setSortBy}>
                  <SelectTrigger className="w-full sm:w-36">
                    <SelectValue placeholder="Sort" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="severity">By Severity</SelectItem>
                    <SelectItem value="risk">By Risk Score</SelectItem>
                    <SelectItem value="file">By File</SelectItem>
                    <SelectItem value="recent">Most Recent</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            {findingSections.length > 0 && (
              <Tabs
                value={activeSection}
                onValueChange={setActiveSection}
              >
                <TabsList
                  variant="line"
                  className="w-full justify-start border-b border-border rounded-none h-auto p-0 gap-0"
                >
                  {findingSections.map(({ id, title, findings }) => (
                    <TabsTrigger
                      key={id}
                      value={id}
                      className="rounded-none pb-2.5 pr-2"
                    >
                      {title}
                      <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-xs font-semibold tabular-nums">
                        {findings.length}
                      </span>
                    </TabsTrigger>
                  ))}
                </TabsList>
              </Tabs>
            )}
          </div>
          <div className="min-w-0 w-full overflow-hidden mt-6">
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
              <Tabs value={activeSection} onValueChange={setActiveSection}>
                {findingSections.map((section) => (
                  <TabsContent key={section.id} value={section.id}>
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
                  </TabsContent>
                ))}
              </Tabs>
            )}
          </div>
        </div>
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

      {/* AI Triage Chat — shown when scan is complete */}
      {scan.status === "COMPLETED" && <ScanTriageChat scanId={scanId} />}
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

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  if (m < 60) return s > 0 ? `${m}m ${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return rm > 0 ? `${h}h ${rm}m` : `${h}h`;
}

function computeEta(
  startedAt: string | null | undefined,
  scannerProgress:
    | Record<
        string,
        {
          status: string;
          filesCompleted?: number;
          filesTotal?: number;
        }
      >
    | null
    | undefined,
  status: string,
  nowMs: number,
): {
  elapsedText: string | null;
  etaText: string;
  fileProgressText: string | null;
} {
  // Elapsed time
  const started = startedAt ? new Date(startedAt).getTime() : 0;
  const elapsedSec = started > 0 ? Math.max(0, Math.floor((nowMs - started) / 1000)) : 0;
  const elapsedText = elapsedSec > 0 ? `Elapsed: ${formatDuration(elapsedSec)}` : null;

  // Aggregate file progress across all scanners
  let totalFiles = 0;
  let completedFiles = 0;
  if (scannerProgress) {
    for (const s of Object.values(scannerProgress)) {
      if (s.filesTotal && s.filesTotal > 0) {
        totalFiles += s.filesTotal;
        completedFiles += s.status === "DONE" ? s.filesTotal : (s.filesCompleted ?? 0);
      }
    }
  }
  const fileProgressText =
    totalFiles > 0 ? `${completedFiles} / ${totalFiles} files scanned` : null;

  // ETA calculation
  if (status === "QUEUED") {
    return { elapsedText, etaText: "Waiting in queue...", fileProgressText };
  }
  if (status === "PAUSED") {
    return { elapsedText, etaText: "PAUSED", fileProgressText };
  }

  const progress = computeScanProgress(scannerProgress, status);

  // Don't show ETA until we have enough data (>10% progress and >15s elapsed)
  if (progress <= 10 || elapsedSec < 15) {
    return { elapsedText, etaText: "Estimating...", fileProgressText };
  }

  // Prevent division by zero and near-completion edge cases
  if (progress >= 99) {
    return { elapsedText, etaText: "Almost done...", fileProgressText };
  }

  const progressFraction = progress / 100;
  // Formula: if we're at P% done in E seconds,
  // remaining time = E * (1 - P) / P
  const remainingSec = Math.round((elapsedSec * (1 - progressFraction)) / progressFraction);

  // Clamp to reasonable values
  if (remainingSec < 0) {
    return { elapsedText, etaText: "Almost done...", fileProgressText };
  }

  if (remainingSec < 60) {
    return { elapsedText, etaText: "< 1 min remaining", fileProgressText };
  }

  return {
    elapsedText,
    etaText: `~${formatDuration(remainingSec)} remaining`,
    fileProgressText,
  };
}

function formatScanMetadataLine(scan: {
  sourceType: string;
  sourceRef?: string | null;
  branch?: string | null;
  commitSha?: string | null;
  prNumber?: number | null;
  createdAt: string;
}): string {
  const parts: string[] = [];
  if (scan.sourceType === "SVN_CHECKOUT") {
    if (scan.sourceRef) parts.push(`SVN: ${scan.sourceRef}`);
    if (scan.commitSha) parts.push(`Rev: ${scan.commitSha}`);
  } else {
    if (scan.prNumber) parts.push(`PR #${scan.prNumber}`);
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
