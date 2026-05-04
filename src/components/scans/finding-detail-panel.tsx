"use client";

import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Copy, ExternalLink, ChevronUp, FileCode } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Sheet, SheetContent } from "@/components/ui/sheet";
import { SeverityBadge } from "./scan-status-badge";
import { SCANNER_LABELS } from "@/lib/constants";
import {
  generateFindingReport,
  maskSecrets,
  type FindingReport,
} from "@/scanners/reports/finding-report-generator";
import type { RawFinding } from "@/scanners/types";

const FINDING_STATUSES = [
  { value: "OPEN", label: "Open", color: "bg-yellow-100 text-yellow-800" },
  { value: "IN_PROGRESS", label: "In Progress", color: "bg-blue-100 text-blue-800" },
  { value: "FALSE_POSITIVE", label: "False Positive", color: "bg-gray-100 text-gray-600" },
  { value: "ACCEPTED_RISK", label: "Accepted Risk", color: "bg-purple-100 text-purple-800" },
  { value: "RESOLVED", label: "Resolved", color: "bg-green-100 text-green-800" },
] as const;

export interface FindingDetailFinding {
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
}

interface FindingDetailPanelProps {
  finding: FindingDetailFinding | null;
  open: boolean;
  onClose: () => void;
  onStatusChange?: (findingId: string, status: string) => void;
}

export interface FindingDetailContentProps {
  finding: FindingDetailFinding;
  onStatusChange?: () => void;
  onCollapse?: () => void;
}

export function FindingDetailContent({
  finding,
  onStatusChange,
  onCollapse,
}: FindingDetailContentProps) {
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const rawFinding = useMemo(() => toRawFinding(finding), [finding]);
  const report = useMemo(
    () => generateFindingReport({ finding: rawFinding }),
    [rawFinding],
  );
  const confidencePercent =
    finding.confidence == null
      ? null
      : Math.round(finding.confidence <= 1 ? finding.confidence * 100 : finding.confidence);

  const handleStatusChange = async (newStatus: string) => {
    try {
      const res = await fetch(`/api/findings/${finding.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error("Failed to update status");
      toast.success(`Status updated to ${newStatus.replace("_", " ").toLowerCase()}`);
      onStatusChange?.();
    } catch {
      toast.error("Failed to update finding status");
    }
  };

  const copy = async (value: string, label: string) => {
    await navigator.clipboard.writeText(value);
    toast.success(`${label} copied`);
  };

  return (
    <div className="sast-report finding-report report-container w-full min-w-0 max-w-full overflow-x-hidden p-1 sm:p-0">
      <div className="finding-card report-container">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 flex-1 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
                {report.severityLabel}
              </span>
              <Badge variant="outline" className="text-xs">
                {SCANNER_LABELS[finding.scanner as keyof typeof SCANNER_LABELS] ||
                  finding.scanner}
              </Badge>
            </div>
            <h2 className="text-balance break-words text-xl font-bold leading-tight text-foreground sm:text-2xl">
              {finding.title}
            </h2>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <HeaderField label="Status">
                <Select value={finding.status || "OPEN"} onValueChange={handleStatusChange}>
                  <SelectTrigger className="h-9 w-full max-w-[220px] text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {FINDING_STATUSES.map((status) => (
                      <SelectItem key={status.value} value={status.value}>
                        <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${status.color}`}>
                          {status.label}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </HeaderField>
              <HeaderField label="Confidence">
                <span className="font-semibold tabular-nums">
                  {confidencePercent == null ? "-" : `${confidencePercent}%`}
                </span>
              </HeaderField>
              <HeaderField label="CWE">
                {finding.cweId ? (
                  <a
                    href={getCweUrl(finding.cweId)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 break-all font-medium text-primary hover:underline"
                  >
                    {finding.cweId}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                ) : (
                  <span className="text-muted-foreground">-</span>
                )}
              </HeaderField>
              <HeaderField label="File / line">
                <span className="break-all font-mono text-xs">{formatLocation(finding)}</span>
              </HeaderField>
              <HeaderField label="Scanner">
                <span>{SCANNER_LABELS[finding.scanner as keyof typeof SCANNER_LABELS] || finding.scanner}</span>
              </HeaderField>
            </div>
            <div className="flex flex-wrap gap-2">
              {finding.ruleId ? (
                <Badge variant="secondary" className="max-w-full font-mono text-xs">
                  {finding.ruleId}
                </Badge>
              ) : null}
              {finding.cveId ? <Badge variant="outline">{finding.cveId}</Badge> : null}
            </div>
          </div>
          {onCollapse ? (
            <Button
              variant="outline"
              size="sm"
              className="shrink-0 gap-1.5"
              onClick={(e) => {
                e.stopPropagation();
                onCollapse();
              }}
            >
              <ChevronUp className="h-4 w-4" aria-hidden />
              Collapse
            </Button>
          ) : null}
        </div>
      </div>

      <div className="report-container mt-4 max-h-[min(88vh,1800px)] w-full min-w-0 space-y-5 overflow-x-hidden overflow-y-auto overscroll-contain pb-4">
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="gap-1.5"
            disabled={!finding.snippet}
            onClick={() => copy(maskSecrets(finding.snippet || ""), "Vulnerable code")}
          >
            <Copy className="h-3.5 w-3.5" />
            Copy vulnerable code
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={() => copy(report.markdown, "Full report")}
          >
            <Copy className="h-3.5 w-3.5" />
            Copy full report
          </Button>
        </div>

        {finding.snippet ? (
          <ReportSection title="Affected code" icon={<FileCode className="h-4 w-4" />}>
            <CodeBlock code={maskSecrets(finding.snippet)} />
          </ReportSection>
        ) : null}

        <FindingReportSections report={report} />

        <section className="report-section">
          <button
            type="button"
            className="report-section-header flex w-full min-w-0 items-center justify-between gap-2 text-left"
            onClick={() => setAdvancedOpen((value) => !value)}
          >
            <span>Advanced details</span>
            <span className="text-xs text-muted-foreground">{advancedOpen ? "Hide" : "Show"}</span>
          </button>
          {advancedOpen ? (
            <div className="section-content min-w-0 space-y-3">
              <DetailRow label="Rule ID" value={finding.ruleId} />
              <DetailRow label="Scanner" value={finding.scanner} />
              <DetailRow label="Confidence" value={confidencePercent == null ? undefined : `${confidencePercent}%`} />
              <References metadata={finding.metadata} />
              {finding.metadata ? <CodeBlock code={JSON.stringify(finding.metadata, null, 2)} /> : null}
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}

function FindingReportSections({ report }: { report: FindingReport }) {
  return (
    <>
      <ReportSection title="Vulnerability Description">
        <div className="space-y-2">
          {report.vulnerabilityDescription.map((paragraph, index) => (
            <p key={index} className="report-paragraph text-sm text-muted-foreground">
              {paragraph}
            </p>
          ))}
        </div>
      </ReportSection>
      <ReportSection title="Weakness Classification">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[420px] border-collapse text-sm">
            <tbody>
              {report.weaknessClassification.map(([label, value]) => (
                <tr key={label} className="border-b border-border last:border-0">
                  <td className="w-1/3 bg-muted/40 px-3 py-2 font-semibold text-foreground">
                    {label}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </ReportSection>
      <ReportSection title="Steps to Reproduce">
        <p className="report-paragraph mb-3 text-sm text-muted-foreground">
          <span className="font-semibold text-foreground">Prerequisites: </span>
          Run the application in an authorized local or staging environment with test data and logs visible.
        </p>
        <ol className="list-decimal space-y-2 pl-5 text-sm text-muted-foreground">
          {report.reproductionSteps.map((step, index) => (
            <li key={index} className="report-paragraph pl-1">
              <span className="font-semibold text-foreground">Step {index + 1} — </span>
              {step}
            </li>
          ))}
        </ol>
      </ReportSection>
      <ReportSection title="Expected vs Actual Behaviour">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-green-200 bg-green-50 p-3">
            <p className="mb-1 text-sm font-semibold text-green-900">Expected Behaviour</p>
            <p className="report-paragraph text-sm text-green-900/80">{report.expectedBehavior}</p>
          </div>
          <div className="rounded-lg border border-orange-200 bg-orange-50 p-3">
            <p className="mb-1 text-sm font-semibold text-orange-900">Actual Behaviour</p>
            <p className="report-paragraph text-sm text-orange-900/80">{report.actualBehavior}</p>
          </div>
        </div>
      </ReportSection>
      <ReportSection title="Proof of Concept Payload">
        <CodeBlock code={report.proofOfConceptPayload} />
        <p className="report-paragraph mt-3 text-sm text-muted-foreground">{report.exploitExample}</p>
      </ReportSection>
      <ReportSection title="Impact">
        <p className="report-paragraph text-sm text-muted-foreground">{report.impact}</p>
        <p className="mt-3 text-sm font-semibold text-foreground">Scope Limitations</p>
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
          {report.scopeLimitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      </ReportSection>
      <ReportSection title="Remediation">
        <p className="mb-1 text-sm font-semibold text-foreground">Fix Applied by Application Team</p>
        <p className="report-paragraph text-sm text-muted-foreground">{report.recommendedFix}</p>
        <p className="mt-3 text-sm font-semibold text-foreground">General Remediation Guidance</p>
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
          {report.remediationGuidance.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </ReportSection>
      <ReportSection title="References">
        {report.references.length ? (
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            {report.references.map((reference) => (
              <li key={reference} className="break-all">
                {reference}
              </li>
            ))}
          </ul>
        ) : (
          <p className="report-paragraph text-sm text-muted-foreground">No external references mapped.</p>
        )}
      </ReportSection>
    </>
  );
}

function HeaderField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">{label}</p>
      <div className="report-paragraph mt-1 text-sm">{children}</div>
    </div>
  );
}

function ReportSection({
  title,
  icon,
  children,
}: {
  title: string;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="report-section">
      <header className="report-section-header flex min-w-0 items-center gap-2">
        {icon ? <span className="shrink-0 text-muted-foreground">{icon}</span> : null}
        <span className="min-w-0 flex-1 break-words">{title}</span>
      </header>
      <div className="section-content min-w-0">{children}</div>
    </section>
  );
}

function CodeBlock({ code }: { code: string }) {
  return (
    <pre className="code-block m-0 min-w-0">
      <code className="block min-w-0 whitespace-pre-wrap break-words">{code}</code>
    </pre>
  );
}

function DetailRow({ label, value }: { label: string; value?: string | null }) {
  if (!value) return null;
  return (
    <p className="report-paragraph text-sm">
      <span className="font-semibold text-muted-foreground">{label}: </span>
      <span className="break-all">{value}</span>
    </p>
  );
}

function References({ metadata }: { metadata?: Record<string, unknown> }) {
  const refs = metadata?.references;
  const list = Array.isArray(refs) ? refs.filter((item): item is string => typeof item === "string") : [];
  if (!list.length) return null;
  return (
    <div>
      <p className="mb-1 text-sm font-semibold text-muted-foreground">References</p>
      <ul className="list-disc space-y-1 pl-5 text-sm">
        {list.map((ref) => (
          <li key={ref} className="break-all">
            {ref}
          </li>
        ))}
      </ul>
    </div>
  );
}

function toRawFinding(finding: FindingDetailFinding): RawFinding {
  return {
    scanner: finding.scanner as RawFinding["scanner"],
    severity: finding.severity as RawFinding["severity"],
    title: finding.title,
    description: finding.description,
    filePath: finding.filePath,
    startLine: finding.startLine,
    endLine: finding.endLine,
    snippet: finding.snippet,
    ruleId: finding.ruleId,
    cweId: finding.cweId,
    cveId: finding.cveId,
    confidence: finding.confidence,
    metadata: finding.metadata,
  };
}

function formatLocation(finding: FindingDetailFinding): string {
  if (!finding.filePath) return "-";
  if (finding.startLine == null) return finding.filePath;
  if (finding.endLine != null && finding.endLine !== finding.startLine) {
    return `${finding.filePath}:${finding.startLine}-${finding.endLine}`;
  }
  return `${finding.filePath}:${finding.startLine}`;
}

function getCweUrl(cweId: string): string {
  return `https://cwe.mitre.org/data/definitions/${cweId.replace("CWE-", "")}.html`;
}

export function FindingDetailPanel({
  finding,
  open,
  onClose,
  onStatusChange,
}: FindingDetailPanelProps) {
  if (!finding) return null;

  return (
    <Sheet open={open} onOpenChange={(nextOpen) => !nextOpen && onClose()}>
      <SheetContent className="flex h-full w-full min-w-0 max-w-full flex-col overflow-hidden p-0 sm:max-w-2xl">
        <ScrollArea className="min-h-0 min-w-0 flex-1">
          <div className="min-w-0 max-w-full p-4">
            <FindingDetailContent
              finding={finding}
              onStatusChange={() => onStatusChange?.(finding.id, finding.status ?? "OPEN")}
            />
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}
