"use client";

import { useState, useEffect, useMemo } from "react";
import { useSession } from "next-auth/react";
import { useParams } from "next/navigation";
import { useScanPolling, useFindings } from "@/hooks/use-scan-polling";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  FINDING_SECTIONS,
  groupFindingsBySection,
} from "@/lib/finding-sections";
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
  Ban,
  AlertTriangle,
  RotateCcw,
  Trash2,
  Pause,
  Play,
  Check,
  Clock,
  Timer,
  Siren,
  Shield,
  CheckCircle2,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { mutate } from "swr";
import { useRouter } from "next/navigation";
import { nextFindingSelection } from "@/lib/create-scan-validation";
import { runOpenFixPrFlow } from "@/lib/open-fix-pr-flow";
import { ScanTriageChat } from "@/components/scans/scan-triage-chat";

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

  // The selected tab is a server-side filter, not a slice of an already-fetched
  // page. Without this a category whose findings sort below the page limit shows
  // "0 of 38" and an empty table: the findings exist, they were simply never
  // fetched. Selecting the tab now asks for exactly that scanner's findings.
  const sectionScanners = FINDING_SECTIONS.find(
    (section) => section.id === activeSection,
  )?.scanners;

  const findingFilters = useMemo(
    () =>
      sectionScanners?.length
        ? { ...filters, scanner: sectionScanners.join(",") }
        : filters,
    [filters, sectionScanners],
  );

  const {
    findings,
    scannerCounts,
    pagination,
    refresh: refreshFindings,
  } = useFindings(
    scanId,
    findingFilters,
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

  // Choose an initial tab from the scan-wide totals. Only when none is selected
  // yet: re-running on every refresh would override whatever the user picked.
  useEffect(() => {
    if (activeSection) return;
    const sections = groupFindingsBySection([], scannerCounts);
    if (sections.length > 0) setActiveSection(sections[0].id);
  }, [activeSection, scannerCounts]);

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
        <div className="flex items-center justify-center gap-2 py-20 text-slate-500">
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent" />
          <span className="text-sm">Loading scan...</span>
        </div>
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
        <div className="flex flex-col items-center justify-center gap-3 py-20 text-slate-500">
          <AlertTriangle className="h-8 w-8 text-red-400" />
          <p className="text-sm font-medium text-red-600">Scan not found</p>
        </div>
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
  // Grand total across every category, from the scan-wide per-scanner counts.
  // The table below is filtered to the selected tab, so a "500 of N" here would
  // describe the page rather than the scan; show the plain total instead.
  const scannerCountTotal = Object.values(scannerCounts).reduce(
    (sum, n) => sum + n,
    0,
  );
  const visibleFindingCount = String(scannerCountTotal || totalFindings);
  const findingSections = groupFindingsBySection(visibleFindings, scannerCounts);

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
      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
        <div className="flex flex-col gap-4 p-5 sm:p-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-1 min-w-0">
            <div className="flex min-w-0 flex-wrap items-center gap-2 sm:gap-3">
              <h1 className="truncate text-lg font-bold text-slate-900 sm:text-xl dark:text-slate-50">
                {scan.project?.name || "Scan"}
              </h1>
              <Badge variant="secondary" className="rounded-md border-slate-200 bg-slate-100 text-xs font-semibold text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
                {scan.scanType}
              </Badge>
              <ScanStatusBadge status={scan.status} />
              {scan.status === "COMPLETED" && (
                <GateResultBadge result={scan.gateResult} />
              )}
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {formatScanMetadataLine(scan)}
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5 shrink-0">
            {canDelete && (
              <Button
                variant="outline"
                className="h-8 gap-1 border-slate-300 px-2.5 text-xs text-slate-600 hover:border-red-300 hover:bg-red-50 hover:text-red-700 dark:border-slate-700 dark:text-slate-400"
                disabled={deleting || isRunning || isPaused}
                onClick={handleDelete}
                title="Delete this scan and all findings"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Delete
              </Button>
            )}
            {canRescan && (
              <Button
                variant="outline"
                className="h-8 gap-1 border-slate-300 px-2.5 text-xs text-slate-600 dark:border-slate-700 dark:text-slate-400"
                disabled={rescanning}
                onClick={handleRescan}
              >
                <RotateCcw className="h-3.5 w-3.5" />
                {rescanning ? "Rescanning..." : "Rescan"}
              </Button>
            )}
            {canManageScan && isRunning && (
              <Button
                variant="outline"
                className="h-8 gap-1 border-slate-300 px-2.5 text-xs text-slate-600 dark:border-slate-700 dark:text-slate-400"
                disabled={pausing}
                onClick={handlePause}
              >
                <Pause className="h-3.5 w-3.5" />
                Pause
              </Button>
            )}
            {canManageScan && (isPaused || isStopped) && (
              <Button
                variant="outline"
                className="h-8 gap-1 border-slate-300 px-2.5 text-xs text-slate-600 dark:border-slate-700 dark:text-slate-400"
                disabled={resuming}
                onClick={handleResume}
              >
                <Play className="h-3.5 w-3.5" />
                {resuming ? "Resuming..." : isStopped ? "Restart" : "Resume"}
              </Button>
            )}
            {canManageScan && isActive && (
              <Button
                variant="outline"
                className="h-8 gap-1 border-slate-300 px-2.5 text-xs text-slate-600 dark:border-slate-700 dark:text-slate-400"
                onClick={handleCancel}
              >
                <Ban className="h-3.5 w-3.5" />
                Cancel
              </Button>
            )}
            {hasReportableFindings && (
              <div className="ml-1 flex items-center gap-0.5 border-l border-slate-200 pl-2 dark:border-slate-700">
                <Button
                  variant="ghost"
                  className="h-8 gap-1 px-2 text-xs text-slate-500 hover:text-indigo-600"
                  onClick={() =>
                    window.open(`/api/scans/${scanId}/findings/export?format=csv`, "_blank")
                  }
                >CSV</Button>
                <Button
                  variant="ghost"
                  className="h-8 gap-1 px-2 text-xs text-slate-500 hover:text-indigo-600"
                  onClick={() =>
                    window.open(`/api/scans/${scanId}/findings/export?format=pdf`, "_blank")
                  }
                >PDF</Button>
                {scan.status === "COMPLETED" && (
                  <Button
                    variant="ghost"
                    className="h-8 gap-1 px-2 text-xs text-slate-500 hover:text-indigo-600"
                    onClick={() => router.push(`/scans/${scanId}/compliance`)}
                  >Compliance</Button>
                )}
                {scan.status === "COMPLETED" && (
                  <>
                    <Button
                      variant="ghost"
                      className="h-8 gap-1 px-2 text-xs text-slate-500 hover:text-indigo-600"
                      onClick={() =>
                        window.open(`/api/scans/${scanId}/artifacts/cyclonedx`, "_blank")
                      }
                    >SBOM (CDX)</Button>
                    <Button
                      variant="ghost"
                      className="h-8 gap-1 px-2 text-xs text-slate-500 hover:text-indigo-600"
                      onClick={() =>
                        window.open(`/api/scans/${scanId}/artifacts/spdx`, "_blank")
                      }
                    >SBOM (SPDX)</Button>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Progress bar for active scans */}
      {isActive && (
        <div className="overflow-hidden rounded-xl border border-indigo-200 bg-gradient-to-r from-indigo-50/80 to-white shadow-sm dark:border-indigo-900/50 dark:from-indigo-950/30 dark:to-slate-950">
          <div className="px-5 py-5 sm:px-6">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="flex h-6 w-6 items-center justify-center rounded-md bg-indigo-100 dark:bg-indigo-900/40">
                    <div className="h-3 w-3 animate-spin rounded-full border-2 border-indigo-600 border-t-transparent dark:border-indigo-400" />
                  </div>
                  <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                    {isPaused ? "Scan paused" : "Scanning..."}
                  </span>
                </div>
                <span className="text-xs font-medium text-indigo-600 dark:text-indigo-400">
                  {etaInfo?.etaText}
                </span>
              </div>
              <Progress
                value={computeScanProgress(scan.scannerProgress, scan.status)}
                className="h-2 [&>div]:bg-gradient-to-r [&>div]:from-indigo-500 [&>div]:to-blue-500"
              />
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
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
                  <div className="flex flex-wrap gap-1.5">
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
                        variant={info.status === "DONE" ? "default" : "secondary"}
                        className={cn(
                          "gap-1.5 text-xs font-medium",
                          info.status === "DONE"
                            ? "bg-emerald-100 text-emerald-700 hover:bg-emerald-100 dark:bg-emerald-900/30 dark:text-emerald-300"
                            : "bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300",
                        )}
                      >
                        {info.status === "DONE" ? (
                          <>
                            <Check className="h-3 w-3 shrink-0" aria-hidden />
                            <span>{name}</span>
                          </>
                        ) : (
                          <span>
                            {name}{info.filesTotal ? ` (${info.filesCompleted ?? 0}/${info.filesTotal})` : ""}
                          </span>
                        )}
                      </Badge>
                    ))}
                  </div>
                )}
            </div>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      {(hasReportableFindings || isActive) && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:gap-4">
          <div className="rounded-xl border border-red-200 bg-gradient-to-br from-red-50 to-white p-4 shadow-sm transition-all hover:shadow-md dark:border-red-900/40 dark:from-red-950/20 dark:to-slate-950">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-red-100 dark:bg-red-900/40">
                <Siren className="h-3.5 w-3.5 text-red-600 dark:text-red-400" />
              </div>
              <span className="text-xs font-semibold text-red-700 dark:text-red-400">Critical</span>
            </div>
            <p className="mt-2 text-2xl font-bold text-red-700 dark:text-red-400 tabular-nums">{scan.criticalCount}</p>
          </div>
          <div className="rounded-xl border border-orange-200 bg-gradient-to-br from-orange-50 to-white p-4 shadow-sm transition-all hover:shadow-md dark:border-orange-900/40 dark:from-orange-950/20 dark:to-slate-950">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-orange-100 dark:bg-orange-900/40">
                <AlertTriangle className="h-3.5 w-3.5 text-orange-600 dark:text-orange-400" />
              </div>
              <span className="text-xs font-semibold text-orange-700 dark:text-orange-400">High</span>
            </div>
            <p className="mt-2 text-2xl font-bold text-orange-700 dark:text-orange-400 tabular-nums">{scan.highCount}</p>
          </div>
          <div className="rounded-xl border border-yellow-200 bg-gradient-to-br from-yellow-50 to-white p-4 shadow-sm transition-all hover:shadow-md dark:border-yellow-900/40 dark:from-yellow-950/20 dark:to-slate-950">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-yellow-100 dark:bg-yellow-900/40">
                <Shield className="h-3.5 w-3.5 text-yellow-600 dark:text-yellow-400" />
              </div>
              <span className="text-xs font-semibold text-yellow-700 dark:text-yellow-400">Medium</span>
            </div>
            <p className="mt-2 text-2xl font-bold text-yellow-700 dark:text-yellow-400 tabular-nums">{scan.mediumCount}</p>
          </div>
          <div className="rounded-xl border border-blue-200 bg-gradient-to-br from-blue-50 to-white p-4 shadow-sm transition-all hover:shadow-md dark:border-blue-900/40 dark:from-blue-950/20 dark:to-slate-950">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-blue-100 dark:bg-blue-900/40">
                <CheckCircle2 className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400" />
              </div>
              <span className="text-xs font-semibold text-blue-700 dark:text-blue-400">Low</span>
            </div>
            <p className="mt-2 text-2xl font-bold text-blue-700 dark:text-blue-400 tabular-nums">{scan.lowCount}</p>
          </div>
        </div>
      )}

      {/* Auto-resolved banner */}
      {scan.status === "COMPLETED" && (scan as { autoResolvedCount?: number }).autoResolvedCount ? (
        <div className="flex items-center gap-3 rounded-xl border border-emerald-200 bg-gradient-to-r from-emerald-50 to-white px-5 py-3 text-sm text-emerald-800 shadow-sm dark:border-emerald-900/40 dark:from-emerald-950/20 dark:to-slate-950 dark:text-emerald-300">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-emerald-100 dark:bg-emerald-900/40">
            <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
          </div>
          <span className="font-medium">
            <span className="font-bold">{(scan as { autoResolvedCount?: number }).autoResolvedCount}</span>
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
          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950">
            <div className="border-b border-slate-100 px-5 py-4 sm:px-6 dark:border-slate-800">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3">
                  <h2 className="text-lg font-bold text-slate-900 dark:text-slate-50">
                    Findings
                  </h2>
                  <span className="inline-flex items-center rounded-md bg-indigo-50 px-2.5 py-0.5 text-sm font-semibold text-indigo-700 dark:bg-indigo-950/40 dark:text-indigo-300">
                    {visibleFindingCount}
                  </span>
                  {scan.status === "COMPLETED" && (scan as { newFindingCount?: number }).newFindingCount ? (
                    <button
                      type="button"
                      onClick={() => setNewOnlyFilter((v) => !v)}
                      className={cn(
                        "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold transition-colors",
                        newOnlyFilter
                          ? "bg-indigo-600 text-white"
                          : "border border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-100 dark:border-indigo-800 dark:bg-indigo-950/30 dark:text-indigo-300",
                      )}
                    >
                      {(scan as { newFindingCount?: number }).newFindingCount} new
                    </button>
                  ) : null}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Select value={severityFilter} onValueChange={setSeverityFilter}>
                    <SelectTrigger className="h-8 w-full border-slate-300 bg-white text-xs sm:w-[130px] dark:border-slate-600 dark:bg-slate-900">
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
                    <SelectTrigger className="h-8 w-full border-slate-300 bg-white text-xs sm:w-[140px] dark:border-slate-600 dark:bg-slate-900">
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
                    <SelectTrigger className="h-8 w-full border-slate-300 bg-white text-xs sm:w-[130px] dark:border-slate-600 dark:bg-slate-900">
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
                <div className="mt-4">
                  <Tabs value={activeSection} onValueChange={setActiveSection}>
                    <TabsList className="w-full justify-start gap-1 rounded-none border-0 bg-transparent p-0">
                      {findingSections.map(
                        ({ id, title, total }) => (
                          <TabsTrigger
                            key={id}
                            value={id}
                            className="rounded-lg border border-transparent px-3 py-1.5 text-xs font-medium data-[state=active]:border-indigo-200 data-[state=active]:bg-indigo-50 data-[state=active]:text-indigo-700 dark:data-[state=active]:border-indigo-800 dark:data-[state=active]:bg-indigo-950/30 dark:data-[state=active]:text-indigo-300"
                          >
                            {title}
                            {/* Always the scan-wide total for this category.
                                Selecting the tab fetches that scanner's findings
                                from the server, so the table shows all of them
                                regardless of the page limit or severity sort. */}
                            <span className="ml-1.5 rounded-md bg-slate-100 px-1.5 py-0.5 text-[11px] font-semibold tabular-nums text-slate-600 dark:bg-slate-800 dark:text-slate-400">
                              {total}
                            </span>
                          </TabsTrigger>
                        ),
                      )}
                    </TabsList>
                  </Tabs>
                </div>
              )}
            <div className="px-0 sm:px-0">
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
        </div>
        </div>
      )}

      {/* Error / stop details */}
      {scan.errorMessage &&
        (scan.status === "FAILED" || scan.status === "CANCELLED") && (
        <div className="overflow-hidden rounded-xl border border-red-200 bg-gradient-to-br from-red-50 to-white shadow-sm dark:border-red-900/40 dark:from-red-950/20 dark:to-slate-950">
          <div className="flex items-start gap-3 px-5 py-5 sm:px-6">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-100 dark:bg-red-900/40">
              <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400" />
            </div>
            <div className="space-y-2 min-w-0">
              <span className="text-sm font-semibold text-red-700 dark:text-red-400">
                {scan.status === "FAILED" ? "Scan failed" : "Scan cancelled"}
              </span>
              <p className="text-sm leading-relaxed text-slate-700 whitespace-pre-wrap break-words dark:text-slate-300">
                {scan.errorMessage}
              </p>
            </div>
          </div>
        </div>
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

