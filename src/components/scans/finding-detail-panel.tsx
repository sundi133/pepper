"use client";

import type { ReactNode } from "react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { SeverityBadge } from "./scan-status-badge";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SCANNER_LABELS } from "@/lib/constants";
import { Shield, ExternalLink } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";

const FINDING_STATUSES = [
  { value: "OPEN", label: "Open", color: "bg-yellow-100 text-yellow-800" },
  {
    value: "IN_PROGRESS",
    label: "In Progress",
    color: "bg-blue-100 text-blue-800",
  },
  {
    value: "FALSE_POSITIVE",
    label: "False Positive",
    color: "bg-gray-100 text-gray-600",
  },
  {
    value: "ACCEPTED_RISK",
    label: "Accepted Risk",
    color: "bg-purple-100 text-purple-800",
  },
  {
    value: "RESOLVED",
    label: "Resolved",
    color: "bg-green-100 text-green-800",
  },
] as const;

interface Finding {
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
  finding: Finding | null;
  open: boolean;
  onClose: () => void;
  onStatusChange?: (findingId: string, status: string) => void;
}

type FindingDetailInlineProps = {
  finding: Finding | null;
  onStatusChange?: (findingId: string, status: string) => void;
};

interface FindingReport {
  vulnerabilityName: string;
  summary: string;
  stepsToReproduce: string[];
  impact: string;
  remediation: string[];
}

// ─── CWE/CVE Link Helpers ────────────────────────────────────────────

function getCweUrl(cweId: string): string {
  const num = cweId.replace("CWE-", "");
  return `https://cwe.mitre.org/data/definitions/${num}.html`;
}

function getCveUrl(cveId: string): string {
  return `https://nvd.nist.gov/vuln/detail/${cveId}`;
}

function FindingReportSections({ finding }: { finding: Finding }) {
  const report = buildFindingReport(finding);

  return (
    <section className="space-y-4 rounded-xl border bg-card p-4 shadow-sm">
      <ReportBlock title="Bug / Vulnerability Name">
        <p className="break-words text-base font-semibold leading-snug">
          {report.vulnerabilityName}
        </p>
      </ReportBlock>

      <ReportBlock title="Summary">
        <ReportText text={report.summary} />
      </ReportBlock>

      {report.stepsToReproduce.length > 0 && (
        <ReportBlock title="Steps to Reproduce">
          <ol className="space-y-2">
            {report.stepsToReproduce.map((step, index) => (
              <li key={index} className="flex gap-3 text-sm text-muted-foreground">
                <span className="mt-0.5 font-medium text-foreground">
                  {index + 1}.
                </span>
                <ReportText text={step} />
              </li>
            ))}
          </ol>
        </ReportBlock>
      )}

      <ReportBlock title="Impact">
        <ReportText text={report.impact} />
      </ReportBlock>

      <ReportBlock title="Remediation">
        <ol className="space-y-2">
          {report.remediation.map((step, index) => (
            <li key={index} className="flex gap-3 text-sm text-muted-foreground">
              <span className="mt-0.5 font-medium text-foreground">
                {index + 1}.
              </span>
              <ReportText text={step} />
            </li>
          ))}
        </ol>
      </ReportBlock>
    </section>
  );
}

function ReportBlock({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </p>
      {children}
    </div>
  );
}

function ReportText({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`)/g);
  return (
    <p className="whitespace-pre-wrap break-words text-sm leading-6 text-muted-foreground">
      {parts.map((part, index) =>
        part.startsWith("`") && part.endsWith("`") ? (
          <code
            key={index}
            className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs text-foreground"
          >
            {part.slice(1, -1)}
          </code>
        ) : (
          <span key={index}>{part}</span>
        ),
      )}
    </p>
  );
}

function buildFindingReport(finding: Finding): FindingReport {
  const stored = readStoredReport(finding.metadata?.reportSections);
  if (stored) return stored;

  const recommendation = extractRecommendation(finding.description);
  return {
    vulnerabilityName:
      readString(finding.metadata?.vulnerabilityName, finding.metadata?.title) ||
      formatTitle(finding),
    summary: buildSummary(finding),
    stepsToReproduce: readStringArray(finding.metadata?.stepsToReproduce),
    impact:
      readString(finding.metadata?.impact) ||
      "Based on the available scanner evidence, this finding may affect application confidentiality, integrity, or availability.",
    remediation: readStringArray(finding.metadata?.remediation).length
      ? readStringArray(finding.metadata?.remediation)
      : [
          recommendation ||
            "Fix the affected code path so user-controlled input cannot reach the vulnerable operation without the required security control.",
        ],
  };
}

function readStoredReport(value: unknown): FindingReport | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }

  const report = value as Partial<{
    vulnerabilityName: unknown;
    summary: unknown;
    stepsToReproduce: unknown;
    impact: unknown;
    remediation: unknown;
  }>;

  if (
    typeof report.vulnerabilityName === "string" &&
    typeof report.summary === "string" &&
    typeof report.impact === "string" &&
    Array.isArray(report.remediation)
  ) {
    return {
      vulnerabilityName: report.vulnerabilityName,
      summary: report.summary,
      stepsToReproduce: Array.isArray(report.stepsToReproduce)
        ? report.stepsToReproduce.filter(
            (step): step is string => typeof step === "string",
          )
        : [],
      impact: report.impact,
      remediation: report.remediation.filter(
        (step): step is string => typeof step === "string",
      ),
    };
  }

  return undefined;
}

function buildSummary(finding: Finding): string {
  const location = formatLocation(finding);
  const sink = readString(finding.metadata?.sink);
  const parameter = readString(finding.metadata?.parameter);
  const description = stripGeneratedSections(finding.description);

  return [
    parameter || sink || location
      ? `${parameter ? `User-controlled input from \`${parameter}\`` : "A user-controlled input source"}${sink ? ` reaches \`${sink}\`` : " reaches the affected operation"}${location ? ` in \`${location}\`` : ""}.`
      : "",
    description,
  ]
    .filter(Boolean)
    .join("\n\n");
}

function formatTitle(finding: Finding): string {
  return finding.cweId && !finding.title.includes(finding.cweId)
    ? `${finding.title} — ${finding.cweId}`
    : finding.title;
}

function formatLocation(finding: Finding): string {
  if (!finding.filePath) return "";
  if (!finding.startLine) return finding.filePath;
  return `${finding.filePath}:${finding.startLine}${
    finding.endLine && finding.endLine !== finding.startLine
      ? `-${finding.endLine}`
      : ""
  }`;
}

function stripGeneratedSections(description: string): string {
  return description
    .split(/\nRecommendation:\s*/i)[0]
    .split(/\nAttack Vector:\s*/i)[0]
    .split(/\nExample Request:\s*/i)[0]
    .split(/\nCategory:\s*/i)[0]
    .trim();
}

function extractRecommendation(description: string): string | undefined {
  return description.match(/\nRecommendation:\s*([\s\S]+)/i)?.[1]?.trim();
}

function readString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  return undefined;
}

function readStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

// ─── Component ───────────────────────────────────────────────────────

export function FindingDetailPanel({
  finding,
  open,
  onClose,
  onStatusChange,
}: FindingDetailPanelProps) {
  if (!finding) return null;

  const handleStatusChange = async (newStatus: string) => {
    try {
      const res = await fetch(`/api/findings/${finding.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error("Failed to update status");
      toast.success(
        `Status updated to ${newStatus.replace("_", " ").toLowerCase()}`,
      );
      onStatusChange?.(finding.id, newStatus);
    } catch {
      toast.error("Failed to update finding status");
    }
  };

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-2xl p-0">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-background border-b px-6 py-4">
          <SheetHeader className="space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={finding.severity} />
              <Badge variant="outline" className="text-xs">
                {SCANNER_LABELS[
                  finding.scanner as keyof typeof SCANNER_LABELS
                ] || finding.scanner}
              </Badge>
            </div>
            <SheetTitle className="text-left text-lg leading-tight">
              {finding.title}
            </SheetTitle>
            {/* Status Control */}
            <div className="flex items-center gap-2 pt-1">
              <span className="text-xs text-muted-foreground">Status:</span>
              <Select
                value={finding.status || "OPEN"}
                onValueChange={handleStatusChange}
              >
                <SelectTrigger className="h-7 w-[160px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FINDING_STATUSES.map((s) => (
                    <SelectItem key={s.value} value={s.value}>
                      <span
                        className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${s.color}`}
                      >
                        {s.label}
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <SheetDescription className="text-left flex items-center gap-3 flex-wrap">
              {finding.ruleId && (
                <code className="text-xs bg-muted px-1.5 py-0.5 rounded">
                  {finding.ruleId}
                </code>
              )}
              {finding.cweId && (
                <a
                  href={getCweUrl(finding.cweId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-600 hover:underline flex items-center gap-1"
                >
                  {finding.cweId}
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
              {finding.cveId && (
                <a
                  href={getCveUrl(finding.cveId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-blue-600 hover:underline flex items-center gap-1"
                >
                  {finding.cveId}
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </SheetDescription>
          </SheetHeader>
        </div>

        <ScrollArea className="h-[calc(100vh-10rem)]">
          <div className="space-y-5 px-6 py-5">
            <FindingReportSections finding={finding} />

            {/* Code Snippet */}
            {finding.snippet && (
              <section>
                <h4 className="text-sm font-semibold flex items-center gap-2 mb-2">
                  <Shield className="h-4 w-4 text-muted-foreground" />
                  Vulnerable Code
                </h4>
                <pre className="rounded-lg bg-zinc-950 border border-zinc-800 p-4 text-sm text-zinc-100 overflow-x-auto font-mono leading-relaxed max-h-48">
                  {finding.snippet}
                </pre>
              </section>
            )}

          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}

export function FindingDetailInline({
  finding,
  onStatusChange,
}: FindingDetailInlineProps) {
  if (!finding) return null;

  const handleStatusChange = async (newStatus: string) => {
    try {
      const res = await fetch(`/api/findings/${finding.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) throw new Error("Failed to update status");
      toast.success(
        `Status updated to ${newStatus.replace("_", " ").toLowerCase()}`,
      );
      onStatusChange?.(finding.id, newStatus);
    } catch {
      toast.error("Failed to update finding status");
    }
  };

  return (
    <div className="w-full max-w-full overflow-hidden rounded-xl border bg-card shadow-sm">
      <div className="border-b px-5 py-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <Badge variant="outline" className="text-xs">
                {SCANNER_LABELS[
                  finding.scanner as keyof typeof SCANNER_LABELS
                ] || finding.scanner}
              </Badge>
              {finding.ruleId && (
                <code className="max-w-full break-all rounded bg-muted px-1.5 py-0.5 text-xs">
                  {finding.ruleId}
                </code>
              )}
              {finding.cweId && (
                <a
                  href={getCweUrl(finding.cweId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs text-blue-600 hover:underline"
                >
                  {finding.cweId}
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
              {finding.cveId && (
                <a
                  href={getCveUrl(finding.cveId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs text-blue-600 hover:underline"
                >
                  {finding.cveId}
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </div>
            <h3 className="break-words text-lg font-semibold leading-tight">
              {finding.title}
            </h3>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <Select
              value={finding.status || "OPEN"}
              onValueChange={handleStatusChange}
            >
              <SelectTrigger className="h-8 w-[160px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FINDING_STATUSES.map((s) => (
                  <SelectItem key={s.value} value={s.value}>
                    <span
                      className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${s.color}`}
                    >
                      {s.label}
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      <div className="w-full max-w-full space-y-5 overflow-hidden p-5">
        <FindingReportSections finding={finding} />

        {finding.snippet && (
          <section>
            <h4 className="mb-2 flex items-center gap-2 text-sm font-semibold">
              <Shield className="h-4 w-4 text-muted-foreground" />
              Vulnerable Code
            </h4>
            <pre className="max-h-64 max-w-full overflow-x-auto whitespace-pre-wrap break-words rounded-lg border border-zinc-800 bg-zinc-950 p-4 font-mono text-sm leading-relaxed text-zinc-100">
              {finding.snippet}
            </pre>
          </section>
        )}
      </div>
    </div>
  );
}
