"use client";

import { useState } from "react";
import { useParams } from "next/navigation";
import useSWR from "swr";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import { toast } from "sonner";
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

interface FrameworkReport {
  framework: string;
  fileName: string;
  totalControls: number;
  impactedControls: number;
  controlSummary: ControlSummary[];
  statusCounts: Record<string, number>;
  findings: FindingMapping[];
}

function csvEscape(value: string | number | null | undefined): string {
  const stringValue = value == null ? "" : String(value);
  return `"${stringValue.replace(/"/g, '""')}"`;
}

export default function ComplianceReportPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const { data, isLoading, error, mutate } = useSWR(
    `/api/scans/${scanId}/compliance`,
    jsonFetcher,
  );
  const { data: scanMeta } = useSWR(`/api/scans/${scanId}`, jsonFetcher, {
    revalidateOnFocus: false,
  });
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const reports: FrameworkReport[] = data?.reports || [];
  const frameworkNames = reports.map((report) => report.framework);
  const activeFrameworks =
    selectedFrameworks.length === 0
      ? frameworkNames
      : selectedFrameworks.filter((name) => frameworkNames.includes(name));

  async function handleRegenerate() {
    try {
      await fetch(`/api/scans/${scanId}/compliance`, { method: "DELETE" });
      toast.success("Cache cleared — regenerating report...");
      mutate();
    } catch {
      toast.error("Failed to regenerate");
    }
  }

  const complianceShellCrumbs = [
    { label: "Dashboard", href: "/dashboard" },
    { label: "Projects", href: "/projects" },
    { label: "Scan", href: `/scans/${scanId}` },
    { label: "Compliance" },
  ];

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageBreadcrumb items={complianceShellCrumbs} />
        <div className="flex flex-col items-center justify-center py-20 gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-muted-foreground">
            Generating compliance report using AI...
          </p>
          <p className="text-xs text-muted-foreground">
            This may take 30-60 seconds for large scans
          </p>
        </div>
      </div>
    );
  }

  if (error || !data || data.error) {
    return (
      <div className="space-y-6">
        <PageBreadcrumb items={complianceShellCrumbs} />
        <div className="text-center py-12 space-y-4">
          <p className="text-destructive">
            {data?.error || "Failed to load compliance report"}
          </p>
          <Link href={`/scans/${scanId}`}>
            <Button variant="outline">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Scan
            </Button>
          </Link>
        </div>
      </div>
    );
  }

  const visibleReports = reports.filter((report) =>
    activeFrameworks.includes(report.framework),
  );

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

  function toggleFramework(framework: string, checked: boolean) {
    setSelectedFrameworks((current) => {
      const selected = current.length === 0 ? frameworkNames : current;
      if (checked) {
        return selected.includes(framework) ? selected : [...selected, framework];
      }

      if (selected.length === 1) return selected;
      return selected.filter((name) => name !== framework);
    });
  }

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
          {data.generatedAt && (
            <p className="text-xs text-muted-foreground ml-[72px]">
              Generated: {new Date(data.generatedAt).toLocaleString()}
            </p>
          )}
        </div>
        <div className="flex gap-2">
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
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Frameworks</CardTitle>
          <CardDescription>
            Select one or more frameworks to display in this report.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSelectedFrameworks(frameworkNames)}
              disabled={frameworkNames.length === activeFrameworks.length}
            >
              Select All
            </Button>
            <span className="text-sm text-muted-foreground self-center">
              Showing {visibleReports.length} of {reports.length} frameworks
            </span>
          </div>
          <div className="flex flex-wrap gap-4">
            {reports.map((report) => (
              <label
                key={report.framework}
                className="flex items-center gap-3 rounded-md border px-3 py-2 text-sm"
              >
                <Checkbox
                  checked={activeFrameworks.includes(report.framework)}
                  onCheckedChange={(checked) =>
                    toggleFramework(report.framework, checked === true)
                  }
                />
                <span className="font-medium">{report.framework}</span>
                <Badge variant="outline">{report.impactedControls} impacted</Badge>
              </label>
            ))}
          </div>
        </CardContent>
      </Card>

      {visibleReports.map((report) => (
        <div key={report.framework} className="space-y-6">
          {/* Framework Summary */}
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardContent className="pt-6">
                <div className="text-sm text-muted-foreground">Framework</div>
                <p className="text-lg font-bold">{report.framework}</p>
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
