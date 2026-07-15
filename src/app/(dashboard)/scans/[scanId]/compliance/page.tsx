"use client";

import { useState, useEffect, useRef } from "react";
import { useParams } from "next/navigation";
import useSWR from "swr";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { SeverityBadge } from "@/components/scans/scan-status-badge";
import { SCANNER_LABELS } from "@/lib/constants";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  ArrowLeft,
  BookOpen,
  Download,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Loader2,
} from "lucide-react";
import Link from "next/link";
import { jsonFetcher } from "@/lib/fetcher";
import { PageBreadcrumb } from "@/components/layout/page-breadcrumb";

const THEME_COLORS: Record<string, string> = {
  Organizational:
    "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-400",
  People: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-400",
  Physical:
    "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-400",
  Technological:
    "bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-400",
  "OWASP Top 10":
    "bg-slate-100 text-slate-800 dark:bg-slate-900 dark:text-slate-300",
};

const RELEVANCE_COLORS: Record<string, string> = {
  direct:
    "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-400 border-red-200",
  supporting:
    "bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-400 border-yellow-200",
  related:
    "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 border-gray-200",
};

interface ControlMapping {
  controlId: string;
  title: string;
  theme: string;
  relevance: string;
  reasoning: string;
  confidence?: number;
  verified?: boolean;
  verificationNote?: string;
}

interface FindingMapping {
  id: string;
  title: string;
  severity: string;
  scanner: string;
  cweId: string | null;
  filePath: string | null;
  startLine: number | null;
  status: string;
  controls: ControlMapping[];
}

interface ControlSummary {
  controlId: string;
  title: string;
  theme: string;
  findingCount: number;
  criticalHighCount: number;
  directCount: number;
}

interface CoverageBucketEntry {
  controlId: string;
  title: string;
  theme: string;
  coverage: string;
  findingCount: number;
  criticalHighCount: number;
  reason?: string;
}

interface FrameworkReport {
  framework: string;
  slug?: string;
  version?: string | null;
  mappingSource?: "agentic" | "crosswalk" | "llm";
  fileName: string;
  totalControls: number;
  impactedControls: number;
  coverage?: { assessable: number; partial: number; notAssessable: number };
  buckets?: {
    gapsFound: CoverageBucketEntry[];
    noIssuesDetected: CoverageBucketEntry[];
    notCovered: CoverageBucketEntry[];
  };
  controlSummary: ControlSummary[];
  statusCounts: Record<string, number>;
  findings: FindingMapping[];
}

interface AvailableFramework {
  name: string;
  slug: string;
  version: string | null;
  controls: number;
  deterministic: boolean;
}

function csvEscape(value: string | number | null | undefined): string {
  const stringValue = value == null ? "" : String(value);
  return `"${stringValue.replace(/"/g, '""')}"`;
}

export default function ComplianceReportPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const [mode, setMode] = useState<"deep" | "fast">("deep");
  const [selectedSlugs, setSelectedSlugs] = useState<string[]>([]);
  const [committedSlugs, setCommittedSlugs] = useState<string[]>([]);

  // Cheap framework catalog — lists frameworks WITHOUT running any mapping.
  const { data: listData } = useSWR(
    `/api/scans/${scanId}/compliance?list=1`,
    jsonFetcher,
    { revalidateOnFocus: false },
  );
  const availableFrameworks: AvailableFramework[] =
    listData?.availableFrameworks || [];

  // Models available for the org's configured LLM provider (deep mode only).
  const { data: modelsData } = useSWR(`/api/llm/models`, jsonFetcher, {
    revalidateOnFocus: false,
  });
  const availableModels: string[] = modelsData?.models || [];
  const providerDefaultModel: string | null = modelsData?.defaultModel || null;
  // "" = user hasn't picked one → fall back to the provider default.
  const [model, setModel] = useState<string>("");
  const effectiveModel = model || providerDefaultModel || "";

  const { data: scanMeta } = useSWR(`/api/scans/${scanId}`, jsonFetcher, {
    revalidateOnFocus: false,
  });

  // Streaming state: the report is built live over Server-Sent Events so the
  // user sees each agent action as it happens.
  const [streaming, setStreaming] = useState(false);
  const [progressLog, setProgressLog] = useState<
    { framework?: string; message: string }[]
  >([]);
  const [streamedReports, setStreamedReports] = useState<FrameworkReport[]>([]);
  const [streamMeta, setStreamMeta] = useState<{
    mode?: string;
    commitSha?: string | null;
    generatedAt?: string;
    totalFindings?: number;
  } | null>(null);
  const [streamError, setStreamError] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => () => esRef.current?.close(), []);
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ block: "end" });
  }, [progressLog]);

  function runStream(slugs: string[], m: "deep" | "fast", mdl?: string) {
    if (slugs.length === 0) return;
    esRef.current?.close();
    setStreaming(true);
    setProgressLog([]);
    setStreamedReports([]);
    setStreamMeta(null);
    setStreamError(null);
    // The model override only applies to agentic (deep) mode.
    const modelParam =
      m === "deep" && mdl ? `&model=${encodeURIComponent(mdl)}` : "";
    const es = new EventSource(
      `/api/scans/${scanId}/compliance/stream?mode=${m}&frameworks=${slugs.join(",")}${modelParam}`,
    );
    esRef.current = es;
    es.addEventListener("start", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      setProgressLog((l) => [
        ...l,
        {
          message:
            `Assessing ${d.frameworks.length} framework(s) against ${d.totalFindings} findings` +
            (d.model ? ` using ${d.model}` : "") +
            "…",
        },
      ]);
    });
    es.addEventListener("progress", (e) => {
      const d = JSON.parse((e as MessageEvent).data);
      setProgressLog((l) => [...l, { framework: d.framework, message: d.message }]);
    });
    es.addEventListener("framework", (e) => {
      const r = JSON.parse((e as MessageEvent).data) as FrameworkReport;
      setStreamedReports((prev) => [...prev, r]);
    });
    es.addEventListener("done", (e) => {
      setStreamMeta(JSON.parse((e as MessageEvent).data));
      setStreaming(false);
      es.close();
      esRef.current = null;
    });
    es.addEventListener("error", (e) => {
      const md = (e as MessageEvent).data;
      let msg = "Connection lost";
      if (md) {
        try {
          msg = JSON.parse(md).message || msg;
        } catch {
          /* keep default */
        }
      }
      setStreamError(msg);
      setStreaming(false);
      es.close();
      esRef.current = null;
    });
  }

  async function handleRegenerate() {
    try {
      await fetch(`/api/scans/${scanId}/compliance`, { method: "DELETE" });
    } catch {
      /* cache clear is best-effort */
    }
    runStream(committedSlugs, mode, effectiveModel);
  }

  function toggleSlug(slug: string, checked: boolean) {
    setSelectedSlugs((cur) =>
      checked
        ? Array.from(new Set([...cur, slug]))
        : cur.filter((s) => s !== slug),
    );
  }

  function selectAllSlugs() {
    setSelectedSlugs(availableFrameworks.map((f) => f.slug));
  }

  function handleGenerate() {
    if (selectedSlugs.length === 0) return;
    setCommittedSlugs(selectedSlugs);
    runStream(selectedSlugs, mode, effectiveModel);
  }

  function switchMode(m: "deep" | "fast") {
    setMode(m);
    if (committedSlugs.length > 0) runStream(committedSlugs, m, effectiveModel);
  }

  function switchModel(mdl: string) {
    setModel(mdl);
    if (committedSlugs.length > 0 && mode === "deep")
      runStream(committedSlugs, mode, mdl);
  }

  // Derived view state, mirroring the previous SWR shape.
  const data =
    streamMeta || streamedReports.length
      ? { ...(streamMeta || {}), reports: streamedReports }
      : null;
  const isLoading = streaming;
  const error = streamError;
  const reports: FrameworkReport[] = streamedReports;
  const hasGenerated = committedSlugs.length > 0;

  // With pick-then-run, the whole page never blocks on generation — the report
  // section below switches between idle / loading / error / results.
  const visibleReports = reports;

  const project = scanMeta?.project as
    | { id?: string; name?: string }
    | undefined;
  const complianceBreadcrumbs = [
    { label: "Dashboard", href: "/dashboard" },
    { label: "Projects", href: "/projects" },
    ...(project?.id && project?.name
      ? [{ label: project.name, href: `/projects/${project.id}` }]
      : []),
    {
      label: scanMeta?.scanType
        ? `${String(scanMeta.scanType)} scan`
        : "Scan",
      href: `/scans/${scanId}`,
    },
    { label: "Compliance" },
  ];

  function handleExportCsv() {
    const lines = [
      [
        "Framework",
        "Finding ID",
        "Finding Title",
        "Severity",
        "Scanner",
        "CWE",
        "File Path",
        "Start Line",
        "Status",
        "Control ID",
        "Control Title",
        "Control Theme",
        "Relevance",
        "Reasoning",
      ].join(","),
    ];

    for (const report of visibleReports) {
      for (const finding of report.findings) {
        if (finding.controls.length === 0) {
          lines.push(
            [
              report.framework,
              finding.id,
              finding.title,
              finding.severity,
              finding.scanner,
              finding.cweId,
              finding.filePath,
              finding.startLine,
              finding.status,
              "",
              "",
              "",
              "",
              "",
            ]
              .map(csvEscape)
              .join(","),
          );
          continue;
        }

        for (const control of finding.controls) {
          lines.push(
            [
              report.framework,
              finding.id,
              finding.title,
              finding.severity,
              finding.scanner,
              finding.cweId,
              finding.filePath,
              finding.startLine,
              finding.status,
              control.controlId,
              control.title,
              control.theme,
              control.relevance,
              control.reasoning,
            ]
              .map(csvEscape)
              .join(","),
          );
        }
      }
    }

    const csv = lines.join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `compliance-${scanId.slice(0, 8)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <PageBreadcrumb items={complianceBreadcrumbs} />

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <Link href={`/scans/${scanId}`}>
              <Button variant="ghost" size="sm">
                <ArrowLeft className="mr-1 h-4 w-4" />
                Back
              </Button>
            </Link>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <BookOpen className="h-6 w-6" />
              Compliance Report
            </h1>
          </div>
          {data?.generatedAt && (
            <p className="text-xs text-muted-foreground ml-[72px]">
              Generated: {new Date(data.generatedAt).toLocaleString()}
            </p>
          )}
        </div>
        <div className="flex gap-2">
          <div className="flex items-center rounded-md border p-0.5" role="group" aria-label="Mapping mode">
            <button
              type="button"
              onClick={() => switchMode("deep")}
              disabled={streaming}
              className={`rounded px-2.5 py-1 text-xs font-medium transition-colors disabled:opacity-50 ${
                mode === "deep"
                  ? "bg-purple-600 text-white"
                  : "text-muted-foreground hover:text-foreground"
              }`}
              title="Agentic AI mapping: grounded reasoning + self-verification (slower, higher accuracy)"
            >
              Agentic
            </button>
            <button
              type="button"
              onClick={() => switchMode("fast")}
              disabled={streaming}
              className={`rounded px-2.5 py-1 text-xs font-medium transition-colors disabled:opacity-50 ${
                mode === "fast"
                  ? "bg-green-600 text-white"
                  : "text-muted-foreground hover:text-foreground"
              }`}
              title="Deterministic CWE crosswalk only (instant, reproducible, no LLM)"
            >
              Fast
            </button>
          </div>
          {mode === "deep" && availableModels.length > 0 && (
            <Select value={effectiveModel} onValueChange={switchModel} disabled={streaming}>
              <SelectTrigger
                className="h-8 w-[190px] text-xs"
                title="LLM model used for agentic compliance mapping"
              >
                <SelectValue placeholder="Model" />
              </SelectTrigger>
              <SelectContent>
                {availableModels.map((m) => (
                  <SelectItem key={m} value={m} className="text-xs">
                    {m}
                    {m === providerDefaultModel ? " (default)" : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          {data && !streaming && (
            <>
              <Button variant="outline" size="sm" onClick={handleRegenerate}>
                <RefreshCw className="mr-2 h-3.5 w-3.5" />
                Regenerate
              </Button>
              <Button variant="outline" onClick={handleExportCsv}>
                <Download className="mr-2 h-4 w-4" />
                Export CSV
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  const json = JSON.stringify(data, null, 2);
                  const blob = new Blob([json], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `compliance-${scanId.slice(0, 8)}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              >
                <Download className="mr-2 h-4 w-4" />
                Export JSON
              </Button>
            </>
          )}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Select frameworks to run</CardTitle>
          <CardDescription>
            Pick which frameworks to assess this scan against. Only the selected
            frameworks are mapped — nothing runs until you click Generate.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={selectAllSlugs}
              disabled={selectedSlugs.length === availableFrameworks.length}
            >
              Select all
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSelectedSlugs([])}
              disabled={selectedSlugs.length === 0}
            >
              Clear
            </Button>
            <span className="text-sm text-muted-foreground self-center">
              {selectedSlugs.length} selected
            </span>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {availableFrameworks.map((fw) => (
              <label
                key={fw.slug}
                className="flex items-start gap-3 rounded-md border px-3 py-2 text-sm cursor-pointer hover:bg-accent/50"
              >
                <Checkbox
                  className="mt-0.5"
                  checked={selectedSlugs.includes(fw.slug)}
                  onCheckedChange={(checked) =>
                    toggleSlug(fw.slug, checked === true)
                  }
                />
                <span className="space-y-0.5">
                  <span className="font-medium block">{fw.name}</span>
                  <span className="flex flex-wrap items-center gap-1">
                    {fw.version && (
                      <Badge variant="outline" className="text-[10px]">
                        {fw.version}
                      </Badge>
                    )}
                    <span className="text-xs text-muted-foreground">
                      {fw.controls} controls
                    </span>
                  </span>
                </span>
              </label>
            ))}
            {availableFrameworks.length === 0 && (
              <span className="text-sm text-muted-foreground">
                Loading frameworks…
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 pt-1">
            <Button
              onClick={handleGenerate}
              disabled={selectedSlugs.length === 0 || isLoading}
            >
              {isLoading ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : (
                <ShieldCheck className="mr-2 h-4 w-4" />
              )}
              {hasGenerated ? "Regenerate for selection" : "Generate report"}
              {selectedSlugs.length > 0 ? ` (${selectedSlugs.length})` : ""}
            </Button>
            {mode === "deep" && (
              <span className="text-xs text-muted-foreground">
                Agentic mode runs the LLM per framework — pick only what you need.
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Result states */}
      {!hasGenerated && (
        <div className="text-center py-16 text-muted-foreground">
          <ShieldCheck className="h-8 w-8 mx-auto mb-3 opacity-50" />
          <p>Select one or more frameworks above and click Generate.</p>
        </div>
      )}
      {/* Live agent activity log */}
      {(streaming || progressLog.length > 0) && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              {streaming ? (
                <Loader2 className="h-4 w-4 animate-spin text-primary" />
              ) : (
                <ShieldCheck className="h-4 w-4 text-green-600" />
              )}
              {streaming ? "Agents working…" : "Run complete"}
            </CardTitle>
            <CardDescription>
              {mode === "deep"
                ? "Grounding findings, reasoning about controls, and verifying each mapping."
                : "Deterministic CWE crosswalk."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="max-h-56 overflow-y-auto rounded-md bg-muted/40 p-3 font-mono text-xs leading-relaxed">
              {progressLog.map((entry, i) => (
                <div key={i} className="flex gap-2">
                  {entry.framework && (
                    <span className="text-muted-foreground shrink-0">
                      [{entry.framework}]
                    </span>
                  )}
                  <span>{entry.message}</span>
                </div>
              ))}
              <div ref={logEndRef} />
            </div>
          </CardContent>
        </Card>
      )}
      {error && (
        <div className="text-center py-12 space-y-3">
          <p className="text-destructive">
            {error || "Failed to generate compliance report"}
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={() => runStream(committedSlugs, mode, effectiveModel)}
          >
            <RefreshCw className="mr-2 h-3.5 w-3.5" />
            Retry
          </Button>
        </div>
      )}

      {visibleReports.map((report) => (
        <div key={report.framework} className="space-y-6">
          {/* Framework Summary */}
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardContent className="pt-6">
                <div className="text-sm text-muted-foreground">Framework</div>
                <p className="text-lg font-bold">{report.framework}</p>
                <div className="mt-1 flex flex-wrap items-center gap-1">
                  {report.version && (
                    <Badge variant="outline" className="text-xs">
                      {report.version}
                    </Badge>
                  )}
                  {report.mappingSource && (
                    <Badge
                      variant="outline"
                      className={
                        report.mappingSource === "crosswalk"
                          ? "text-xs bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-400 border-green-200"
                          : "text-xs bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-400 border-purple-200"
                      }
                    >
                      {report.mappingSource === "crosswalk"
                        ? "Deterministic (CWE crosswalk)"
                        : report.mappingSource === "agentic"
                          ? "Agentic AI (grounded + verified)"
                          : "AI-mapped"}
                    </Badge>
                  )}
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-sm text-muted-foreground">
                  Controls Impacted
                </div>
                <p className="text-2xl font-bold">
                  {report.impactedControls}{" "}
                  <span className="text-sm font-normal text-muted-foreground">
                    / {report.totalControls}
                  </span>
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-sm text-muted-foreground flex items-center gap-1">
                  <AlertTriangle className="h-3.5 w-3.5 text-destructive" />
                  Direct Violations
                </div>
                <p className="text-2xl font-bold text-destructive">
                  {report.controlSummary.reduce((a, c) => a + c.directCount, 0)}
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-sm text-muted-foreground flex items-center gap-1">
                  <ShieldCheck className="h-3.5 w-3.5 text-green-500" />
                  Resolved
                </div>
                <p className="text-2xl font-bold text-green-600">
                  {report.statusCounts?.resolved || 0}
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Coverage — what SAST can and cannot attest */}
          {report.buckets && report.coverage && (
            <Card>
              <CardHeader>
                <CardTitle>SAST Coverage — {report.framework}</CardTitle>
                <CardDescription>
                  What this scan can attest. &ldquo;No issues detected&rdquo; is
                  not the same as compliant, and controls SAST cannot assess need
                  other evidence.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-3 sm:grid-cols-3">
                  <div className="rounded-lg border border-red-200 dark:border-red-900 p-3">
                    <div className="text-sm text-muted-foreground">
                      Gaps found
                    </div>
                    <p className="text-2xl font-bold text-destructive">
                      {report.buckets.gapsFound.length}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      controls with findings
                    </p>
                  </div>
                  <div className="rounded-lg border border-green-200 dark:border-green-900 p-3">
                    <div className="text-sm text-muted-foreground">
                      No issues detected
                    </div>
                    <p className="text-2xl font-bold text-green-600">
                      {report.buckets.noIssuesDetected.length}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      assessable, no findings
                    </p>
                  </div>
                  <div className="rounded-lg border border-muted p-3">
                    <div className="text-sm text-muted-foreground">
                      Not covered by SAST
                    </div>
                    <p className="text-2xl font-bold text-muted-foreground">
                      {report.buckets.notCovered.length}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      needs other evidence
                    </p>
                  </div>
                </div>
                {report.buckets.notCovered.length > 0 && (
                  <details className="text-sm">
                    <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
                      Show {report.buckets.notCovered.length} controls not
                      assessable by SAST
                    </summary>
                    <ul className="mt-2 space-y-1 pl-4">
                      {report.buckets.notCovered.map((c) => (
                        <li key={c.controlId} className="text-muted-foreground">
                          <span className="font-medium text-foreground">
                            {c.controlId}
                          </span>{" "}
                          {c.title}
                          {c.reason ? ` — ${c.reason}` : ""}
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
              </CardContent>
            </Card>
          )}

          {/* Control Summary */}
          <Card>
            <CardHeader>
              <CardTitle>Impacted Controls — {report.framework}</CardTitle>
              <CardDescription>
                Controls with security findings, sorted by direct violation
                count
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-24">Control</TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead className="w-32">Theme</TableHead>
                    <TableHead className="w-20 text-center">Direct</TableHead>
                    <TableHead className="w-20 text-center">Total</TableHead>
                    <TableHead className="w-28 text-center">
                      Crit/High
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {report.controlSummary.map((control) => (
                    <TableRow key={control.controlId}>
                      <TableCell className="font-mono font-bold">
                        {control.controlId}
                      </TableCell>
                      <TableCell className="max-w-[min(20rem,40vw)] align-top text-sm leading-snug break-words">
                        {control.title}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`text-[10px] ${THEME_COLORS[control.theme] || ""}`}
                        >
                          {control.theme}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-center">
                        {control.directCount > 0 ? (
                          <span className="text-destructive font-bold">
                            {control.directCount}
                          </span>
                        ) : (
                          "0"
                        )}
                      </TableCell>
                      <TableCell className="text-center">
                        {control.findingCount}
                      </TableCell>
                      <TableCell className="text-center">
                        {control.criticalHighCount > 0 ? (
                          <span className="text-destructive font-bold">
                            {control.criticalHighCount}
                          </span>
                        ) : (
                          "0"
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* Finding-to-Control Detail */}
          <Card>
            <CardHeader>
              <CardTitle>Finding → Control Mapping</CardTitle>
              <CardDescription>
                Each finding with its mapped controls and relevance level. Hover
                over a control badge for the LLM&apos;s reasoning.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <TooltipProvider>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-20">Severity</TableHead>
                      <TableHead>Finding</TableHead>
                      <TableHead className="w-24">Scanner</TableHead>
                      <TableHead>Mapped Controls</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {report.findings.map((f) => (
                      <TableRow key={f.id}>
                        <TableCell>
                          <SeverityBadge severity={f.severity} />
                        </TableCell>
                        <TableCell className="max-w-md align-top break-words">
                          <div>
                            <p className="font-medium text-sm leading-snug">
                              {f.title}
                            </p>
                            {f.cweId && (
                              <span className="text-xs text-muted-foreground">
                                {f.cweId}
                              </span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {SCANNER_LABELS[
                              f.scanner as keyof typeof SCANNER_LABELS
                            ] || f.scanner}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {f.controls.map((c, i) => (
                              <Tooltip key={i}>
                                <TooltipTrigger asChild>
                                  <Badge
                                    variant="outline"
                                    className={`text-[10px] font-mono cursor-help ${RELEVANCE_COLORS[c.relevance] || ""}`}
                                  >
                                    {c.controlId}
                                    {c.verified && (
                                      <span
                                        className="ml-1 text-green-600"
                                        title="Verified"
                                      >
                                        ✓
                                      </span>
                                    )}
                                    {typeof c.confidence === "number" && (
                                      <span className="ml-1 opacity-70">
                                        {Math.round(c.confidence * 100)}%
                                      </span>
                                    )}
                                  </Badge>
                                </TooltipTrigger>
                                <TooltipContent
                                  side="bottom"
                                  className="max-w-lg whitespace-normal text-left leading-relaxed"
                                >
                                  <p className="font-medium">
                                    {c.controlId}: {c.title}
                                  </p>
                                  <p className="text-xs mt-2 text-muted-foreground">
                                    [{c.relevance}] {c.reasoning}
                                  </p>
                                  {(typeof c.confidence === "number" ||
                                    c.verified !== undefined) && (
                                    <p className="text-xs mt-1 text-muted-foreground">
                                      {typeof c.confidence === "number" &&
                                        `Confidence ${Math.round(c.confidence * 100)}%`}
                                      {c.verified !== undefined &&
                                        ` · ${c.verified ? "verified ✓" : "unverified"}`}
                                      {c.verificationNote
                                        ? ` — ${c.verificationNote}`
                                        : ""}
                                    </p>
                                  )}
                                </TooltipContent>
                              </Tooltip>
                            ))}
                            {f.controls.length === 0 && (
                              <span className="text-xs text-muted-foreground">
                                No mapping
                              </span>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TooltipProvider>
            </CardContent>
          </Card>

          {/* Legend */}
          <div className="flex items-center gap-4 text-xs text-muted-foreground px-1">
            <span className="font-medium">Relevance:</span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2 h-2 rounded-full bg-red-500" />
              Direct — finding directly violates this control
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2 h-2 rounded-full bg-yellow-500" />
              Supporting — indicates a gap in this control
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2 h-2 rounded-full bg-gray-400" />
              Related — tangentially connected
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}
