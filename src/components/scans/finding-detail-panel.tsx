"use client";

import { useState } from "react";
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
import { SCANNER_LABELS, isPatternBasedScanner } from "@/lib/constants";
import {
  buildStoredFindingReport,
  findingReportSummaryLead,
  renderReportPlainText,
  stripReportMarkdown,
} from "@/lib/finding-report";
import {
  githubBlobLineUrl,
  parseGithubRepo,
  resolveGithubRepoUrlForOpenPr,
} from "@/lib/github-source-link";
import {
  type FixPrScanSourceContext,
  fixPrUnavailableReason,
  resolveGithubRepoForFixPr,
} from "@/lib/open-fix-pr-client";
import { runOpenFixPrFlow } from "@/lib/open-fix-pr-flow";
import { ExternalLink, Sparkles, GitPullRequest, Copy, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

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

/** Scan/repo context for GitHub line links, AI fix, and opening a fix PR. */
export type FindingScanSourceContext = FixPrScanSourceContext;

interface FindingDetailPanelProps {
  finding: Finding | null;
  open: boolean;
  onClose: () => void;
  onStatusChange?: (findingId: string, status: string) => void;
  sourceContext?: FindingScanSourceContext;
}

type FindingDetailInlineProps = {
  finding: Finding | null;
  onStatusChange?: (findingId: string, status: string) => void;
  sourceContext?: FindingScanSourceContext;
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

function formatFindingLocation(finding: Finding): string {
  if (!finding.filePath) return "";
  const line = finding.startLine;
  const end = finding.endLine;
  const linePart =
    line != null
      ? end != null && end !== line
        ? `:${line}-${end}`
        : `:${line}`
      : "";
  return `${finding.filePath}${linePart}`;
}

function githubCodeUrl(
  source: FindingScanSourceContext | undefined,
  finding: Finding,
): string | null {
  if (!source || !finding.filePath) return null;
  const repoUrl = resolveGithubRepoUrlForOpenPr({
    projectRepoUrl: source.repoUrl,
    scanSourceType: source.sourceType,
    scanSourceRef: source.scanSourceRef,
  });
  if (!repoUrl) return null;
  return githubBlobLineUrl({
    repoUrl,
    commitSha: source.commitSha,
    branch: source.branch,
    defaultBranch: source.defaultBranch ?? "main",
    filePath: finding.filePath,
    startLine: finding.startLine,
  });
}

function PatternMatchReport({ finding }: { finding: Finding }) {
  const body = stripGeneratedSections(finding.description);
  return (
    <section className="finding-detail-report surface-card min-w-0 max-w-full space-y-4 overflow-hidden border-border/60 bg-muted/30 p-4">
      <p className="text-sm leading-relaxed text-muted-foreground">
        This finding comes from an <strong className="text-foreground">LLM-powered analysis</strong>{" "}
        of your code. Review the finding, confirm the issue in code, and use{" "}
        <strong className="text-foreground">Suggest AI fix</strong> to get fix recommendations.
      </p>
      {body ? (
        <ReportBlock title="Scanner message">
          <ReportRichText text={body} />
        </ReportBlock>
      ) : null}
      {finding.snippet ? (
        <ReportBlock title="Code evidence">
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-border/60 bg-background/80 p-3 text-xs font-mono leading-relaxed text-foreground">
            {finding.snippet}
          </pre>
        </ReportBlock>
      ) : null}
    </section>
  );
}

function InlineBackticks({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`)/g);
  return (
    <>
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
    </>
  );
}

const REPORT_SUMMARY_LABELS =
  "What is wrong|Where|Why it is exploitable|How to validate the fix|Attack path|Fix";

/** Summary with bold inline field labels (What is wrong, Where, …). */
function ReportSummaryText({ text }: { text: string }) {
  const clean = stripReportMarkdown(text);
  const paragraphs = clean.split(/\n\n+/).filter(Boolean);

  return (
    <div className="space-y-3">
      {paragraphs.map((para, i) => {
        const labelMatch = para.match(
          new RegExp(
            `^(${REPORT_SUMMARY_LABELS}):\\s*([\\s\\S]*)$`,
            "i",
          ),
        );
        if (labelMatch) {
          return (
            <p
              key={i}
              className="whitespace-pre-wrap break-words text-sm leading-6 text-muted-foreground"
            >
              <span className="font-bold text-foreground">{labelMatch[1]}:</span>{" "}
              <InlineBackticks text={labelMatch[2].trim()} />
            </p>
          );
        }
        return (
          <p
            key={i}
            className="whitespace-pre-wrap break-words text-sm leading-6 text-muted-foreground"
          >
            <InlineBackticks text={para} />
          </p>
        );
      })}
    </div>
  );
}

/** Renders report text (plain; strips stray markdown markers). */
function ReportRichText({ text }: { text: string }) {
  const clean = stripReportMarkdown(text);
  const segments = clean.split(/(```[\w-]*\n[\s\S]*?```)/g);
  return (
    <div className="space-y-2">
      {segments.map((seg, i) => {
        if (seg.startsWith("```")) {
          const cleaned = seg
            .replace(/^```[\w-]*\n?/, "")
            .replace(/\n?```\s*$/u, "");
          return (
            <pre
              key={i}
              className="max-w-full overflow-x-auto rounded-lg border border-border/60 bg-muted/80 p-3 text-xs font-mono leading-relaxed text-foreground"
            >
              {cleaned}
            </pre>
          );
        }
        if (!seg) return null;
        return (
          <p
            key={i}
            className="whitespace-pre-wrap break-words text-sm leading-6 text-muted-foreground"
          >
            <InlineBackticks text={seg} />
          </p>
        );
      })}
    </div>
  );
}

function ReportPlainList({ items }: { items: string[] }) {
  return (
    <div className="space-y-3">
      {items.map((step, index) => (
        <p key={index} className="text-sm leading-relaxed text-muted-foreground">
          <ReportRichText text={step} />
        </p>
      ))}
    </div>
  );
}

function FindingReportSections({ finding }: { finding: Finding }) {
  if (isPatternBasedScanner(finding.scanner)) {
    return <PatternMatchReport finding={finding} />;
  }

  // SAST findings get professional format with metadata cards
  if (finding.scanner === "SAST_LLM") {
    return <SastReportSections finding={finding} />;
  }

  // Secrets findings get professional format with secret table
  if (finding.scanner === "SECRETS_LLM") {
    return <SecretsReportSections finding={finding} />;
  }

  // Container findings get professional CVE format
  if (finding.scanner === "CONTAINER") {
    return <ContainerReportSections finding={finding} />;
  }

  // Zero-Day findings get professional business logic format
  if (finding.scanner === "ZERO_DAY") {
    return <ZeroDayReportSections finding={finding} />;
  }

  // Special formatting for IaC and SCA findings
  if (finding.scanner === "IAC" || finding.scanner === "SCA") {
    return <IaCScaReportSections finding={finding} />;
  }

  const report = buildStoredFindingReport(finding);

  return (
    <section className="finding-detail-report interactive-card min-w-0 max-w-full space-y-4 overflow-hidden p-4">
      <ReportBlock title="Bug / Vulnerability Name">
        <p className="break-words text-base font-semibold leading-snug">
          {stripReportMarkdown(report.vulnerabilityName)}
        </p>
      </ReportBlock>

      <ReportBlock title="Summary">
        <ReportSummaryText text={report.summary} />
      </ReportBlock>

      {report.stepsToReproduce.length > 0 && (
        <ReportBlock title="Steps to Reproduce">
          <ReportPlainList items={report.stepsToReproduce} />
        </ReportBlock>
      )}

      <ReportBlock title="Impact">
        <ReportRichText text={report.impact} />
      </ReportBlock>

      <ReportBlock title="Remediation">
        <ReportPlainList items={report.remediation} />
      </ReportBlock>
    </section>
  );
}

/** Professional SAST findings format with metadata cards and LLM-generated sections */
function SastReportSections({ finding }: { finding: Finding }) {
  const getSeverityColor = () => {
    switch (finding.severity?.toUpperCase()) {
      case "CRITICAL":
        return { bg: "bg-red-50", border: "border-red-200", icon: "🔴", text: "text-red-700" };
      case "HIGH":
        return { bg: "bg-orange-50", border: "border-orange-200", icon: "🟠", text: "text-orange-700" };
      case "MEDIUM":
        return { bg: "bg-amber-50", border: "border-amber-200", icon: "🟡", text: "text-amber-700" };
      case "LOW":
        return { bg: "bg-blue-50", border: "border-blue-200", icon: "🔵", text: "text-blue-700" };
      default:
        return { bg: "bg-gray-50", border: "border-gray-200", icon: "ℹ️", text: "text-gray-700" };
    }
  };

  const color = getSeverityColor();
  const report = buildStoredFindingReport(finding);

  return (
    <section className="finding-detail-report min-w-0 max-w-full space-y-4 overflow-hidden">
      <div className={`${color.bg} border ${color.border} rounded-lg p-4`}>
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-2xl">{color.icon}</span>
              <h2 className={`text-lg font-bold ${color.text}`}>{finding.severity?.toUpperCase()}</h2>
              <span className="text-base font-semibold text-gray-900">
                {stripReportMarkdown(report.vulnerabilityName)}
              </span>
            </div>
          </div>
          {finding.cweId && (
            <div className={`px-3 py-1 rounded-full border ${color.border} ${color.text} text-sm font-semibold`}>
              {finding.cweId}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {finding.metadata?.route ? (
          <MetadataCard icon="📍" label="Endpoint" value={(finding.metadata.route as string)} />
        ) : null}
        {finding.filePath ? (
          <MetadataCard icon="📄" label="File" value={`${finding.filePath}:${finding.startLine || 1}`} />
        ) : null}
        <MetadataCard icon="⚠️" label="Severity" value={finding.severity?.toUpperCase() || "UNKNOWN"} />
        {finding.metadata?.weaknessClass ? (
          <MetadataCard icon="🛡️" label="Category" value={(finding.metadata.weaknessClass as string)} />
        ) : null}
      </div>

      <div className="space-y-4">
        {report.summary ? (
          <ReportSection icon="ℹ️" title="Summary" color={color}>
            <ReportSummaryText text={report.summary} />
          </ReportSection>
        ) : null}

        {finding.metadata?.exploitPreconditions ? (
          <ReportSection icon="❓" title="Root Cause" color={color}>
            <p className="text-sm text-gray-700">
              {finding.metadata.exploitPreconditions as string}
            </p>
          </ReportSection>
        ) : null}

        {finding.metadata?.whyExploitable ? (
          <ReportSection icon="⚡" title="Why This Is Exploitable" color={color}>
            <p className="text-sm text-gray-700">
              {finding.metadata.whyExploitable as string}
            </p>
          </ReportSection>
        ) : null}

        {report.stepsToReproduce.length > 0 ? (
          <ReportSection icon="🧪" title="Steps to Reproduce" color={color}>
            <ol className="space-y-2 text-sm text-gray-700">
              {report.stepsToReproduce.map((step, i) => (
                <li key={i} className="flex gap-2">
                  <span className="font-semibold min-w-6">{i + 1}.</span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </ReportSection>
        ) : null}

        {report.impact ? (
          <ReportSection icon="💥" title="Impact" color={color}>
            <ReportRichText text={report.impact} />
          </ReportSection>
        ) : null}

        {report.remediation.length > 0 ? (
          <ReportSection icon="🛠️" title="Remediation" color={color}>
            <ul className="space-y-2 text-sm text-gray-700">
              {report.remediation.map((fix, i) => (
                <li key={i} className="flex gap-2">
                  <span>•</span>
                  <span>{fix}</span>
                </li>
              ))}
            </ul>
          </ReportSection>
        ) : null}

        {finding.metadata?.terminalCommand ? (
          <div className="mt-4 p-4 bg-gray-900 rounded-lg">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-white font-bold">Terminal (Example)</span>
            </div>
            <pre className="text-green-400 text-xs font-mono overflow-x-auto">
              <code>{finding.metadata.terminalCommand as string}</code>
            </pre>
          </div>
        ) : null}
      </div>
    </section>
  );
}

function MetadataCard({ icon, label, value }: { icon: string; label: string; value: string }) {
  return (
    <div className="flex items-start gap-2 p-3 bg-white rounded-lg border border-gray-200">
      <span className="text-lg mt-0.5">{icon}</span>
      <div className="min-w-0">
        <p className="text-xs font-semibold text-gray-600">{label}</p>
        <p className="text-sm font-semibold text-gray-900 truncate">{value}</p>
      </div>
    </div>
  );
}

function ReportSection({
  icon,
  title,
  children,
  color,
}: {
  icon: string;
  title: string;
  children: React.ReactNode;
  color: { text: string };
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-lg">{icon}</span>
        <p className={`text-sm font-bold ${color.text}`}>{title}</p>
      </div>
      <div className="pl-6">{children}</div>
    </div>
  );
}

/** Professional Secrets findings format with secret details table */
function SecretsReportSections({ finding }: { finding: Finding }) {
  const credentialType = (finding.metadata?.credentialType as string) || "";
  const maskedValue = (finding.metadata?.maskedValue as string) || "";
  const location = finding.filePath ? `${finding.filePath}:${finding.startLine || 1}` : "";
  const impact = (finding.metadata?.impact as string) || "";
  const evidence = (finding.metadata?.evidence as string) || "";
  const remediation = (finding.metadata?.remediation as string) || "";
  const validationSteps = (finding.metadata?.validationSteps as string[]) || [];

  return (
    <section className="finding-detail-report min-w-0 max-w-full space-y-4 overflow-hidden">
      {/* Secrets Identified Card */}
      <div className="bg-red-50 border border-red-200 rounded-lg p-4">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex items-start gap-3">
            <span className="text-2xl">🔗</span>
            <div>
              <h2 className="text-lg font-bold text-gray-900">Secrets Identified</h2>
              <p className="text-sm text-gray-700 mt-1">
                The following secret value was found exposed in the source code.
              </p>
            </div>
          </div>
          <button className="px-3 py-2 border border-red-300 text-red-700 rounded hover:bg-red-100 text-sm font-semibold flex items-center gap-2">
            📋 Copy
          </button>
        </div>

        {/* Secrets Details Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-red-200">
                <th className="px-3 py-2 text-left font-semibold text-gray-700">Secret Type</th>
                <th className="px-3 py-2 text-left font-semibold text-gray-700">Secret Value</th>
                <th className="px-3 py-2 text-left font-semibold text-gray-700">Location</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-red-100">
                <td className="px-3 py-3 font-semibold text-red-700">{credentialType}</td>
                <td className="px-3 py-3 font-mono text-xs text-gray-900 break-all bg-gray-50 rounded">
                  {maskedValue}
                </td>
                <td className="px-3 py-3">
                  <a href="#" className="text-blue-600 hover:underline font-semibold">
                    📄 {location}
                  </a>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Warning Banner */}
        <div className="mt-4 p-3 bg-yellow-50 border border-yellow-200 rounded flex gap-2">
          <span className="text-lg">⚠️</span>
          <p className="text-sm text-yellow-800">
            This secret was found in source code and may have been committed to version control.
          </p>
        </div>
      </div>

      {/* How to Validate - from LLM */}
      {validationSteps.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-lg">🔍</span>
            <p className="text-sm font-bold text-blue-700">How to Validate</p>
          </div>
          <div className="pl-6 text-sm text-gray-700">
            {evidence ? <p className="mb-2">{evidence}</p> : null}
            <ul className="space-y-1">
              {validationSteps.map((step, i) => (
                <li key={i} className="flex gap-2">
                  <span>•</span>
                  <span>{step}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {/* Risk - from LLM */}
      {impact ? (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-lg">🛡️</span>
            <p className="text-sm font-bold text-red-700">Risk</p>
          </div>
          <div className="pl-6 text-sm text-gray-700">
            <p>{impact}</p>
          </div>
        </div>
      ) : null}

      {/* Recommendations - from LLM */}
      {remediation ? (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-lg">✅</span>
            <p className="text-sm font-bold text-green-700">Recommendations</p>
          </div>
          <div className="pl-6 text-sm text-gray-700">
            <ul className="space-y-2">
              {remediation.split(/\n|;/).filter(Boolean).map((item, i) => (
                <li key={i} className="flex gap-2">
                  <span>•</span>
                  <span>{item.trim()}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      ) : null}
    </section>
  );
}

/** Container CVE findings use IaC-style simple format with package/image details */
function ContainerReportSections({ finding }: { finding: Finding }) {
  const cveId = finding.cveId || finding.ruleId || "";
  const packageName = (finding.metadata?.packageName as string) || "";
  const packageVersion = (finding.metadata?.packageVersion as string) || "";
  const fixedVersion = (finding.metadata?.fixedVersion as string) || "";
  const image = (finding.metadata?.image as string) || "";
  const location = finding.filePath ? `${finding.filePath}:${finding.startLine || 1}` : "";
  const report = buildStoredFindingReport(finding);

  const getSeverityColor = () => {
    switch (finding.severity?.toUpperCase()) {
      case "CRITICAL":
        return { icon: "🔴", text: "text-red-700" };
      case "HIGH":
        return { icon: "🟠", text: "text-orange-700" };
      case "MEDIUM":
        return { icon: "🟡", text: "text-amber-700" };
      case "LOW":
        return { icon: "🔵", text: "text-blue-700" };
      default:
        return { icon: "ℹ️", text: "text-gray-700" };
    }
  };

  const severity = getSeverityColor();

  return (
    <section className="finding-detail-report min-w-0 max-w-full space-y-4 overflow-hidden">
      {/* Header with title and CVE */}
      <div className="flex items-start justify-between gap-4 p-4 bg-gray-50 rounded-lg border border-gray-200">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="text-2xl">{severity.icon}</span>
            <h2 className={`text-lg font-bold ${severity.text}`}>{finding.severity?.toUpperCase()}</h2>
            <span className="text-base font-semibold text-gray-900">{finding.title}</span>
          </div>
        </div>
        {cveId && (
          <div className="px-3 py-1 rounded-full border border-gray-300 text-gray-700 text-sm font-semibold">
            {cveId}
          </div>
        )}
      </div>

      {/* Vulnerable Dependency Details */}
      {packageName && (
        <div className="p-4 bg-gray-50 rounded-lg border border-gray-200">
          <p className="text-xs font-semibold text-gray-600 mb-2">Vulnerable Dependency</p>
          <div className="space-y-2">
            {packageName && (
              <p className="font-mono text-sm font-semibold text-gray-900 bg-white p-2 rounded border border-gray-200">
                {packageName}@{packageVersion}
              </p>
            )}
            {fixedVersion && (
              <p className="text-sm text-gray-700">
                <span className="font-semibold">Fix available:</span> {packageName}@{fixedVersion}
              </p>
            )}
            {cveId && (
              <p className="text-sm text-gray-700">
                <span className="font-semibold">CVE:</span> {cveId}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Where - Image Location */}
      {image && (
        <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
          <p className="text-xs font-semibold text-blue-700 mb-2">Where</p>
          <a href="#" className="text-blue-600 hover:underline font-semibold text-sm">
            🐳 {image}
          </a>
          {location && (
            <p className="text-xs text-gray-600 mt-1">Referenced in {location}</p>
          )}
        </div>
      )}

      {/* Description */}
      {finding.description ? (
        <div className="p-4 bg-white rounded-lg border border-gray-200">
          <p className="text-xs font-semibold text-gray-600 mb-2">Description</p>
          <p className="text-sm text-gray-700">{finding.description}</p>
        </div>
      ) : null}

      {/* Summary from report */}
      {report.summary ? (
        <div className="p-4 bg-white rounded-lg border border-gray-200">
          <p className="text-xs font-semibold text-gray-600 mb-2">Summary</p>
          <ReportSummaryText text={report.summary} />
        </div>
      ) : null}

      {/* Remediation */}
      {report.remediation.length > 0 ? (
        <div className="p-4 bg-white rounded-lg border border-gray-200">
          <p className="text-xs font-semibold text-gray-600 mb-2">Remediation</p>
          <ul className="space-y-2 text-sm text-gray-700">
            {report.remediation.map((fix, i) => (
              <li key={i} className="flex gap-2">
                <span>•</span>
                <span>{fix}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

/** Zero-Day findings use SAST-style format with metadata cards */
function ZeroDayReportSections({ finding }: { finding: Finding }) {
  const getSeverityColor = () => {
    switch (finding.severity?.toUpperCase()) {
      case "CRITICAL":
        return { bg: "bg-red-50", border: "border-red-200", icon: "🔴", text: "text-red-700" };
      case "HIGH":
        return { bg: "bg-orange-50", border: "border-orange-200", icon: "🟠", text: "text-orange-700" };
      case "MEDIUM":
        return { bg: "bg-amber-50", border: "border-amber-200", icon: "🟡", text: "text-amber-700" };
      case "LOW":
        return { bg: "bg-blue-50", border: "border-blue-200", icon: "🔵", text: "text-blue-700" };
      default:
        return { bg: "bg-gray-50", border: "border-gray-200", icon: "ℹ️", text: "text-gray-700" };
    }
  };

  const color = getSeverityColor();
  const report = buildStoredFindingReport(finding);
  const category = (finding.metadata?.category as string) || "Business Logic";
  const attackScenario = (finding.metadata?.attackScenario as string) || "";
  const exploitPreconditions = (finding.metadata?.exploitPreconditions as string) || "";

  return (
    <section className="finding-detail-report min-w-0 max-w-full space-y-4 overflow-hidden">
      {/* Header with severity and title */}
      <div className={`${color.bg} border ${color.border} rounded-lg p-4`}>
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-2xl">{color.icon}</span>
              <h2 className={`text-lg font-bold ${color.text}`}>{finding.severity?.toUpperCase()}</h2>
              <span className="text-base font-semibold text-gray-900">
                {stripReportMarkdown(report.vulnerabilityName)}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Metadata Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {finding.filePath ? (
          <MetadataCard icon="📄" label="File" value={`${finding.filePath}:${finding.startLine || 1}`} />
        ) : null}
        <MetadataCard icon="⚠️" label="Severity" value={finding.severity?.toUpperCase() || "UNKNOWN"} />
        {category ? (
          <MetadataCard icon="🎯" label="Type" value={category} />
        ) : null}
      </div>

      {/* Vulnerability Details */}
      <div className="space-y-4">
        {report.summary ? (
          <ReportSection icon="📋" title="Summary" color={color}>
            <ReportSummaryText text={report.summary} />
          </ReportSection>
        ) : null}

        {exploitPreconditions ? (
          <ReportSection icon="❓" title="Root Cause" color={color}>
            <p className="text-sm text-gray-700">{exploitPreconditions}</p>
          </ReportSection>
        ) : null}

        {attackScenario ? (
          <ReportSection icon="⚡" title="Attack Scenario" color={color}>
            <p className="text-sm text-gray-700">{attackScenario}</p>
          </ReportSection>
        ) : null}

        {report.impact ? (
          <ReportSection icon="💥" title="Business Impact" color={color}>
            <ReportRichText text={report.impact} />
          </ReportSection>
        ) : null}

        {report.remediation.length > 0 ? (
          <ReportSection icon="🛠️" title="Remediation" color={color}>
            <ul className="space-y-2 text-sm text-gray-700">
              {report.remediation.map((fix, i) => (
                <li key={i} className="flex gap-2">
                  <span>•</span>
                  <span>{fix}</span>
                </li>
              ))}
            </ul>
          </ReportSection>
        ) : null}
      </div>
    </section>
  );
}

/** Simplified report for IaC and SCA findings - shows Issue, Why It Matters, Customer Impact, and Remediation */
function IaCScaReportSections({ finding }: { finding: Finding }) {
  const packageName = (finding.metadata?.packageName as string) ||
                     (finding.metadata?.image as string) ||
                     finding.title;
  const severity = finding.metadata?.severity || finding.severity;

  const getSeverityIcon = () => {
    switch (finding.severity?.toUpperCase()) {
      case "CRITICAL":
        return { bg: "bg-red-100", text: "text-red-600", icon: "⚠️", label: "CRITICAL" };
      case "HIGH":
        return { bg: "bg-orange-100", text: "text-orange-600", icon: "🔴", label: "HIGH" };
      case "MEDIUM":
        return { bg: "bg-amber-100", text: "text-amber-600", icon: "🟡", label: "MEDIUM" };
      case "LOW":
        return { bg: "bg-blue-100", text: "text-blue-600", icon: "🔵", label: "LOW" };
      default:
        return { bg: "bg-gray-100", text: "text-gray-600", icon: "ℹ️", label: "INFO" };
    }
  };

  const severity_badge = getSeverityIcon();

  return (
    <section className="finding-detail-report interactive-card min-w-0 max-w-full space-y-6 overflow-hidden p-4">
      <div className="flex items-start justify-between mb-4">
        <h3 className="text-base font-semibold">{finding.title}</h3>
        <div className={`flex items-center gap-2 px-3 py-2 rounded ${severity_badge.bg}`}>
          <span className="text-lg">{severity_badge.icon}</span>
          <span className={`text-sm font-bold ${severity_badge.text}`}>{severity_badge.label}</span>
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <div className="flex h-6 w-6 items-center justify-center rounded bg-blue-100">
            <span className="text-sm font-bold text-blue-600">ℹ</span>
          </div>
          <p className="text-sm font-bold text-foreground">Issue</p>
        </div>
        <div className="space-y-2 pl-8">
          <p className="text-sm text-foreground">{finding.description}</p>
          {packageName && (
            <div className="rounded bg-gray-50 p-3 font-mono text-sm">
              {packageName}
            </div>
          )}
        </div>
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <div className="flex h-6 w-6 items-center justify-center rounded bg-red-100">
            <span className="text-sm font-bold text-red-600">⚠</span>
          </div>
          <p className="text-sm font-bold text-red-600">Why It Matters</p>
        </div>
        <div className="pl-8">
          {(finding.metadata?.exploitPreconditions || finding.metadata?.whyExploitable) ? (
            <p className="text-sm text-foreground">
              {(finding.metadata?.exploitPreconditions as string) ||
               (finding.metadata?.whyExploitable as string)}
            </p>
          ) : (
            <ul className="space-y-1 text-sm text-foreground">
              <li>• Unauthorized access</li>
              <li>• Execution of arbitrary code</li>
              <li>• Data exposure</li>
              <li>• Service disruption</li>
            </ul>
          )}
        </div>
      </div>

      <div className="space-y-2 rounded bg-amber-50 p-4">
        <div className="flex items-center gap-2">
          <span className="text-lg">👥</span>
          <p className="text-sm font-bold text-amber-900">Customer Impact</p>
        </div>
        <p className="text-sm text-amber-900">
          {(finding.metadata?.businessImpact as string) ||
           `The application is running on ${packageName}, which has reached end-of-life and no longer receives security updates. If attackers exploit known vulnerabilities in this version or its dependencies, they could gain unauthorized access, disrupt application services, or potentially expose sensitive customer data. This increases the risk of security incidents and may affect the availability, integrity, and reliability of the service.`}
        </p>
      </div>

      <div className="space-y-2">
        {finding.scanner === "SCA" ? (
          <>
            <p className="text-sm font-bold text-foreground">Vulnerable Dependency</p>
            <div className="pl-4 space-y-2">
              <div className="rounded bg-gray-50 p-3 font-mono text-sm">
                {(finding.metadata?.packageName as string)}@{(finding.metadata?.packageVersion as string) || "unknown"}
              </div>
              {(finding.metadata?.fixVersion) ? (
                <div className="text-sm text-foreground">
                  <p className="font-semibold">Fix available:</p>
                  <p className="pl-2 font-mono">{(finding.metadata?.packageName as string)}@{(finding.metadata?.fixVersion as string)}</p>
                </div>
              ) : null}
              {(finding.cveId) ? (
                <div className="text-sm text-foreground">
                  <p className="font-semibold">CVE:</p>
                  <p className="pl-2 font-mono">{finding.cveId}</p>
                </div>
              ) : null}
            </div>
          </>
        ) : (
          <>
            <p className="text-sm font-bold text-foreground">Where</p>
            <p className="pl-4 font-mono text-sm text-foreground">
              {finding.filePath}:{finding.startLine}
            </p>
          </>
        )}
      </div>

      {(finding.metadata?.validationSteps) ? (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-lg">🧪</span>
            <p className="text-sm font-bold text-foreground">How to Validate</p>
          </div>
          <div className="space-y-2 pl-8">
            {Array.isArray(finding.metadata?.validationSteps) ? (
              (finding.metadata.validationSteps as string[]).map((step: string, i: number) => (
                <div key={i} className="rounded bg-gray-50 p-2 font-mono text-sm">
                  {step}
                </div>
              ))
            ) : typeof finding.metadata?.validationSteps === "string" ? (
              <p className="text-sm text-foreground">
                {finding.metadata.validationSteps as string}
              </p>
            ) : null}
          </div>
        </div>
      ) : null}

      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-lg">🔧</span>
          <p className="text-sm font-bold text-green-600">Remediation</p>
        </div>
        <div className="space-y-2 pl-8">
          {finding.metadata?.remediation ? (
            Array.isArray(finding.metadata.remediation) ? (
              (finding.metadata.remediation as string[]).map((item, i) => (
                <div key={i} className="text-sm text-foreground">
                  • {item}
                </div>
              ))
            ) : (
              <p className="text-sm text-foreground">
                {(finding.metadata.remediation as string)}
              </p>
            )
          ) : (
            <div className="space-y-2 text-sm text-foreground">
              <div>• Use a supported version</div>
              <div>• Update the configuration in {finding.filePath}</div>
              <div>• Rebuild and redeploy the application</div>
            </div>
          )}
        </div>
      </div>
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
      <p className="text-sm font-bold text-foreground">{title}</p>
      {children}
    </div>
  );
}

function buildFindingReport(finding: Finding): FindingReport {
  if (!isPatternBasedScanner(finding.scanner)) {
    const stored = readStoredReport(finding.metadata?.reportSections);
    if (stored) return stored;
  }

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
  const description = stripGeneratedSections(finding.description);
  const lead = findingReportSummaryLead(finding);
  return [lead, description].filter(Boolean).join("\n\n");
}

function formatTitle(finding: Finding): string {
  return finding.cweId && !finding.title.includes(finding.cweId)
    ? `${finding.title} — ${finding.cweId}`
    : finding.title;
}

function stripGeneratedSections(description: string): string {
  return description
    .split(/\nCode evidence:\s*/i)[0]
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

function buildAiAssistPrompt(
  tool: "claude" | "cursor",
  finding: Finding,
  sourceContext?: FindingScanSourceContext,
): string {
  const report = buildFindingReport(finding);
  const repoUrl = sourceContext
    ? resolveGithubRepoUrlForOpenPr({
        projectRepoUrl: sourceContext.repoUrl,
        scanSourceType: sourceContext.sourceType,
        scanSourceRef: sourceContext.scanSourceRef,
      })
    : null;
  const lineUrl = githubCodeUrl(sourceContext, finding);
  const location = formatFindingLocation(finding);
  const assistantName = tool === "claude" ? "Claude Code" : "Cursor";
  const toolHints =
    tool === "claude"
      ? [
          "You are working in Claude Code inside a local repository.",
          "Edit files directly and keep the patch as small as possible.",
          "If you need more context, inspect the repo first, then make the fix.",
        ]
      : [
          "You are working in Cursor inside a local repository.",
          "Edit files directly and keep the patch as small as possible.",
          "If you need more context, inspect the repo first, then make the fix.",
        ];

  return [
    `You are ${assistantName}. Fix the security finding below directly in code.`,
    ...toolHints,
    "After editing, summarize the files changed and how to validate the fix.",
    "Do not give general advice unless it is needed to complete the patch.",
    "",
    "Repository context:",
    repoUrl ? `- Repository: ${repoUrl}` : "- Repository: not available",
    sourceContext?.branch ? `- Branch: ${sourceContext.branch}` : null,
    sourceContext?.commitSha ? `- Commit: ${sourceContext.commitSha}` : null,
    location ? `- Location: ${location}` : null,
    lineUrl ? `- GitHub line: ${lineUrl}` : null,
    finding.ruleId ? `- Rule ID: ${finding.ruleId}` : null,
    finding.cweId ? `- CWE: ${finding.cweId}` : null,
    `- Severity: ${finding.severity}`,
    `- Scanner: ${finding.scanner}`,
    "",
    "Finding report:",
    renderReportPlainText(report),
    "",
    "Output format:",
    "1. Brief diagnosis",
    "2. Files changed",
    "3. Validation",
  ]
    .filter((line): line is string => line !== null)
    .join("\n");
}

function CopyReportButton({ finding }: { finding: Finding }) {
  const [busy, setBusy] = useState(false);

  if (isPatternBasedScanner(finding.scanner)) return null;

  async function copyReport() {
    setBusy(true);
    try {
      const report = buildStoredFindingReport(finding);
      await navigator.clipboard.writeText(renderReportPlainText(report));
      toast.success("Report copied");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to copy report");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className="h-8 gap-1.5 text-xs font-medium"
      disabled={busy}
      onClick={() => void copyReport()}
    >
      <Copy className="h-3.5 w-3.5 shrink-0" aria-hidden />
      {busy ? "Copying…" : "Copy report"}
    </Button>
  );
}

function CopyAiPromptButton({
  finding,
  sourceContext,
  tool,
}: {
  finding: Finding;
  sourceContext?: FindingScanSourceContext;
  tool: "claude" | "cursor";
}) {
  const [busy, setBusy] = useState(false);
  const label = tool === "claude" ? "Copy for Claude" : "Copy for Cursor";

  async function copyPrompt() {
    setBusy(true);
    try {
      const prompt = buildAiAssistPrompt(tool, finding, sourceContext);
      await navigator.clipboard.writeText(prompt);
      toast.success(`${label} copied`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : `Failed to copy ${label.toLowerCase()}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className="h-8 gap-1.5 text-xs font-medium"
      disabled={busy}
      onClick={() => void copyPrompt()}
    >
      <Copy className="h-3.5 w-3.5 shrink-0" aria-hidden />
      {busy ? "Copying…" : label}
    </Button>
  );
}

function FindingActionButtons({
  finding,
  sourceContext,
}: {
  finding: Finding;
  sourceContext?: FindingScanSourceContext;
}) {
  return (
    <div className="flex min-w-0 max-w-full flex-wrap gap-2">
      <CopyReportButton finding={finding} />
      <CopyAiPromptButton finding={finding} sourceContext={sourceContext} tool="claude" />
      <CopyAiPromptButton finding={finding} sourceContext={sourceContext} tool="cursor" />
      {sourceContext?.scanId ? (
        <>
          <SuggestAiFixButton finding={finding} scanId={sourceContext.scanId} />
          <VerifyFpButton finding={finding} onStatusChange={undefined} />
          <OpenFixPrButton finding={finding} sourceContext={sourceContext} />
        </>
      ) : null}
    </div>
  );
}

type VerifyFpResponse = {
  isFalsePositive: boolean;
  confidence: number;
  reasoning: string;
  recommendation: "MARK_FP" | "KEEP_OPEN" | "NEEDS_REVIEW";
  applied: boolean;
};

function VerifyFpButton({
  finding,
  onStatusChange,
}: {
  finding: Finding;
  onStatusChange: (() => void) | undefined;
}) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [marking, setMarking] = useState(false);
  const [data, setData] = useState<VerifyFpResponse | null>(null);

  const alreadyFp = finding.status === "FALSE_POSITIVE";

  async function run() {
    setOpen(true);
    setLoading(true);
    setData(null);
    try {
      const res = await fetch(`/api/findings/${finding.id}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ autoApply: false }),
      });
      const j = (await res.json()) as VerifyFpResponse & { error?: string };
      if (!res.ok) throw new Error(j.error || "Failed to verify finding");
      setData(j);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Verification failed");
      setOpen(false);
    } finally {
      setLoading(false);
    }
  }

  async function markAsFp() {
    setMarking(true);
    try {
      const res = await fetch(`/api/findings/${finding.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          status: "FALSE_POSITIVE",
          statusNote: `AI verification (${Math.round((data?.confidence ?? 0) * 100)}% confidence): ${data?.reasoning ?? ""}`,
        }),
      });
      if (!res.ok) throw new Error("Failed to update status");
      toast.success("Marked as false positive");
      setOpen(false);
      onStatusChange?.();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to mark as FP");
    } finally {
      setMarking(false);
    }
  }

  const verdictColor = data
    ? data.isFalsePositive
      ? "bg-green-100 text-green-800"
      : "bg-red-100 text-red-800"
    : "";

  return (
    <>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        className="h-8 gap-1.5 text-xs font-medium"
        disabled={loading || alreadyFp}
        onClick={() => void run()}
      >
        <ShieldCheck className="h-3.5 w-3.5 shrink-0" aria-hidden />
        {loading ? "Verifying..." : alreadyFp ? "Already FP" : "Verify FP"}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[85vh] max-w-lg gap-0 overflow-hidden p-0 sm:max-w-lg">
          <DialogHeader className="border-b border-border/60 px-6 py-4">
            <DialogTitle className="text-left text-base">
              False Positive Verification
            </DialogTitle>
            <p className="text-left text-xs text-muted-foreground">
              AI-powered analysis of whether this finding is a true or false
              positive.
            </p>
          </DialogHeader>
          <div className="max-h-[calc(85vh-8rem)] overflow-y-auto px-6 py-4 space-y-4">
            {loading ? (
              <p className="text-sm text-muted-foreground">
                Analyzing finding with AI...
              </p>
            ) : data ? (
              <>
                <div className="flex items-center gap-3">
                  <Badge className={verdictColor}>
                    {data.isFalsePositive ? "Likely False Positive" : "Likely True Positive"}
                  </Badge>
                  <span className="text-sm text-muted-foreground">
                    {Math.round(data.confidence * 100)}% confidence
                  </span>
                </div>

                <div className="rounded-lg border border-border/60 bg-muted/30 p-3">
                  <p className="text-sm leading-relaxed text-foreground">
                    {data.reasoning}
                  </p>
                </div>

                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>Recommendation:</span>
                  <Badge variant="outline" className="text-xs">
                    {data.recommendation === "MARK_FP"
                      ? "Mark as False Positive"
                      : data.recommendation === "KEEP_OPEN"
                        ? "Keep Open"
                        : "Needs Manual Review"}
                  </Badge>
                </div>

                {data.isFalsePositive && data.confidence >= 0.8 && (
                  <Button
                    size="sm"
                    variant="default"
                    className="w-full"
                    disabled={marking}
                    onClick={() => void markAsFp()}
                  >
                    {marking
                      ? "Marking..."
                      : "Mark as False Positive"}
                  </Button>
                )}
              </>
            ) : null}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

type SuggestFixResponse = {
  summary: string;
  developerFix: string;
  verificationSteps: string[];
  optionalUnifiedDiff: string | null;
};

function FindingLocationRow({
  finding,
  sourceContext,
}: {
  finding: Finding;
  sourceContext?: FindingScanSourceContext;
}) {
  const loc = formatFindingLocation(finding);
  const gh = githubCodeUrl(sourceContext, finding);
  if (!loc && !gh) return null;
  return (
    <div className="flex flex-wrap items-center gap-2 pt-1">
      {loc ? (
        <code className="max-w-full break-all rounded-md bg-muted px-2 py-1 font-mono text-xs text-foreground">
          {loc}
        </code>
      ) : null}
      {gh ? (
        <Button variant="outline" size="sm" className="h-7 gap-1.5 px-2 text-xs" asChild>
          <a href={gh} target="_blank" rel="noopener noreferrer">
            View on GitHub
            <ExternalLink className="h-3 w-3 shrink-0" />
          </a>
        </Button>
      ) : null}
    </div>
  );
}

function SuggestAiFixButton({
  finding,
  scanId,
}: {
  finding: Finding;
  scanId: string;
}) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<SuggestFixResponse | null>(null);

  async function run() {
    setOpen(true);
    setLoading(true);
    setData(null);
    try {
      const res = await fetch(
        `/api/scans/${scanId}/findings/${finding.id}/suggest-fix`,
        { method: "POST" },
      );
      const j = (await res.json()) as SuggestFixResponse & { error?: string };
      if (!res.ok) {
        throw new Error(j.error || "Failed to generate suggestion");
      }
      setData({
        summary: j.summary,
        developerFix: j.developerFix,
        verificationSteps: j.verificationSteps,
        optionalUnifiedDiff: j.optionalUnifiedDiff,
      });
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to generate suggestion");
      setOpen(false);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        className="h-8 gap-1.5 text-xs font-medium"
        disabled={loading}
        onClick={() => void run()}
      >
        <Sparkles className="h-3.5 w-3.5 shrink-0" aria-hidden />
        {loading ? "Generating…" : "Suggest AI fix"}
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-h-[85vh] max-w-2xl gap-0 overflow-hidden p-0 sm:max-w-2xl">
          <DialogHeader className="border-b border-border/60 px-6 py-4">
            <DialogTitle className="text-left text-base">AI fix suggestion</DialogTitle>
            <p className="text-left text-xs text-muted-foreground">
              Generated with your organization LLM settings or server{" "}
              <code className="rounded bg-muted px-1">LLM_API_KEY</code> /{" "}
              <code className="rounded bg-muted px-1">OPENAI_API_KEY</code>. Review before
              applying; this does not open a pull request automatically.
            </p>
          </DialogHeader>
          <div className="max-h-[calc(85vh-8rem)] overflow-y-auto px-6 py-4 space-y-5">
            {loading ? (
              <p className="text-sm text-muted-foreground">Calling the model…</p>
            ) : data ? (
              <>
                <ReportBlock title="Summary">
                  <ReportRichText text={data.summary} />
                </ReportBlock>
                <ReportBlock title="What to change">
                  <ReportRichText text={data.developerFix || "_No detailed fix text returned._"} />
                </ReportBlock>
                {data.verificationSteps.length > 0 ? (
                  <ReportBlock title="Verify the fix">
                    <ol className="list-decimal space-y-2 pl-4 text-sm text-muted-foreground">
                      {data.verificationSteps.map((s, i) => (
                        <li key={i} className="leading-relaxed">
                          <ReportRichText text={s} />
                        </li>
                      ))}
                    </ol>
                  </ReportBlock>
                ) : null}
                {data.optionalUnifiedDiff ? (
                  <ReportBlock title="Suggested patch (diff)">
                    <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border/60 bg-muted/80 p-3 text-xs font-mono">
                      {data.optionalUnifiedDiff}
                    </pre>
                  </ReportBlock>
                ) : null}
              </>
            ) : null}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}

function OpenFixPrButton({
  finding,
  sourceContext,
}: {
  finding: Finding;
  sourceContext?: FindingScanSourceContext;
}) {
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<"quick" | "agentic">("quick");
  const scanId = sourceContext?.scanId?.trim();
  if (!scanId) return null;

  const blockReason = fixPrUnavailableReason(sourceContext, finding.filePath);
  const hasGithubRepo = Boolean(resolveGithubRepoForFixPr(sourceContext));
  const canOpen = !blockReason;

  async function openPr(fixMode: "quick" | "agentic") {
    let manualRepoUrl: string | undefined;
    if (!hasGithubRepo) {
      const input = window.prompt(
        "Enter the GitHub repository for this fix PR (owner/repo or https://github.com/owner/repo):",
      );
      if (!input?.trim()) return;
      manualRepoUrl = input.trim();
    }

    setMode(fixMode);
    setBusy(true);
    try {
      const outcome = await runOpenFixPrFlow(scanId!, finding.id, {
        repoUrl: manualRepoUrl,
        mode: fixMode,
      });
      if ("redirected" in outcome) return;
      if (!outcome.ok) {
        if (outcome.code !== "CANCELLED") {
          toast.error(outcome.error);
        }
        return;
      }
      toast.success("Pull request opened");
      window.open(outcome.pullRequestUrl, "_blank", "noopener,noreferrer");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to open pull request");
    } finally {
      setBusy(false);
    }
  }

  const busyLabel = mode === "agentic" ? "Analyzing..." : "Opening...";

  const buttons = (
    <>
      <Button
        type="button"
        variant="default"
        size="sm"
        className="h-8 gap-1.5 text-xs font-semibold"
        disabled={busy || !canOpen}
        onClick={() => void openPr("quick")}
      >
        <GitPullRequest className="h-3.5 w-3.5 shrink-0" aria-hidden />
        {busy && mode === "quick" ? busyLabel : "Fix PR"}
      </Button>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        className="h-8 gap-1.5 text-xs font-semibold"
        disabled={busy || !canOpen}
        onClick={() => void openPr("agentic")}
      >
        <Sparkles className="h-3.5 w-3.5 shrink-0" aria-hidden />
        {busy && mode === "agentic" ? busyLabel : "Deep Fix PR"}
      </Button>
    </>
  );

  if (canOpen) {
    return buttons;
  }

  const hint = `${blockReason} Connect GitHub via OAuth when prompted. You can also enter owner/repo when opening the PR.`;

  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex cursor-default gap-2">
            {buttons}
          </span>
        </TooltipTrigger>
        <TooltipContent side="bottom" className="max-w-xs text-balance">
          {hint}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// ─── Component ───────────────────────────────────────────────────────

export function FindingDetailPanel({
  finding,
  open,
  onClose,
  onStatusChange,
  sourceContext,
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
      <SheetContent className="w-full max-w-[100vw] overflow-x-hidden p-0 sm:max-w-2xl">
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
            <FindingLocationRow finding={finding} sourceContext={sourceContext} />
            {/* Status Control */}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <FindingActionButtons finding={finding} sourceContext={sourceContext} />
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

        <ScrollArea className="h-[calc(100vh-10rem)] w-full">
          <div className="min-w-0 space-y-5 overflow-hidden px-6 py-5">
            <FindingReportSections finding={finding} />

          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}

export function FindingDetailInline({
  finding,
  onStatusChange,
  sourceContext,
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
    <div className="finding-detail-inline min-w-0 w-full max-w-full overflow-hidden rounded-xl border bg-card shadow-sm">
      <div className="min-w-0 border-b px-4 py-4 sm:px-5">
        <div className="flex min-w-0 flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="min-w-0 flex-1 space-y-2">
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
            <FindingLocationRow finding={finding} sourceContext={sourceContext} />
          </div>
          <div className="flex min-w-0 max-w-full shrink-0 flex-wrap items-center gap-2">
            <FindingActionButtons finding={finding} sourceContext={sourceContext} />
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

      <div className="min-w-0 w-full max-w-full space-y-5 overflow-hidden p-4 sm:p-5">
        <FindingReportSections finding={finding} />
      </div>
    </div>
  );
}
