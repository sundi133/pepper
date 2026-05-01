"use client";

import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Sheet, SheetContent } from "@/components/ui/sheet";
import { SeverityBadge } from "./scan-status-badge";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { SCANNER_LABELS } from "@/lib/constants";
import {
  FileCode,
  Shield,
  Info,
  Copy,
  Target,
  Wrench,
  AlertTriangle,
  ExternalLink,
  ChevronUp,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import type { VulnerabilityReportDetails } from "@/lib/security-report";
import { normalizeCustomerFacingText } from "@/lib/report-text";

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

// ─── CWE/CVE Link Helpers ────────────────────────────────────────────

function getCweUrl(cweId: string): string {
  const num = cweId.replace("CWE-", "");
  return `https://cwe.mitre.org/data/definitions/${num}.html`;
}

function getCveUrl(cveId: string): string {
  return `https://nvd.nist.gov/vuln/detail/${cveId}`;
}

export interface FindingDetailContentProps {
  finding: FindingDetailFinding;
  onStatusChange?: () => void;
  onCollapse?: () => void;
}

/** Keys allowed in customer-facing UI (excludes internal/debug metadata.hints). */
const CUSTOMER_REPORT_KEYS = new Set([
  "vulnerabilityName",
  "severity",
  "confidenceLevel",
  "confidenceScore",
  "affectedFilePath",
  "affectedFunction",
  "exactLineNumber",
  "lineRange",
  "language",
  "vulnerableSourceCode",
  "lineByLineExplanation",
  "rootCause",
  "realWorldAttackScenario",
  "advancedAttackerReasoning",
  "attackPreconditions",
  "stepsToReproduce",
  "proofOfConcept",
  "expectedVulnerableBehavior",
  "businessImpact",
  "secureFixExplanation",
  "secureCodeExample",
  "securityTests",
  "regressionPrevention",
]);

function sanitizeReportValue(value: unknown): unknown {
  if (value == null) return value;
  if (typeof value === "string") return normalizeCustomerFacingText(value);
  if (Array.isArray(value)) return value.map(sanitizeReportValue);
  if (typeof value === "object") {
    const o = value as Record<string, unknown>;
    const lineEntry =
      "explanation" in o &&
      typeof o.explanation === "string";
    if (lineEntry) {
      return {
        ...o,
        explanation: normalizeCustomerFacingText(String(o.explanation)),
      };
    }
    return Object.fromEntries(
      Object.entries(o).map(([k, v]) => [k, sanitizeReportValue(v)]),
    );
  }
  return value;
}

function pickCustomerFacingReport(
  finding: FindingDetailFinding,
): Partial<VulnerabilityReportDetails> | null {
  const raw = finding.metadata?.report;
  if (!raw || typeof raw !== "object") return null;
  const src = raw as Record<string, unknown>;
  const picked: Record<string, unknown> = {};
  for (const key of CUSTOMER_REPORT_KEYS) {
    if (src[key] !== undefined) picked[key] = src[key];
  }
  if (Object.keys(picked).length === 0) return null;
  return sanitizeReportValue(picked) as Partial<VulnerabilityReportDetails>;
}

function getReportDetails(
  finding: FindingDetailFinding,
): Partial<VulnerabilityReportDetails> | null {
  return pickCustomerFacingReport(finding);
}

function formatSeverityLabel(severity: string): string {
  const labels: Record<string, string> = {
    CRITICAL: "Critical",
    HIGH: "High",
    MEDIUM: "Medium",
    LOW: "Low",
    INFO: "Informational",
  };
  return labels[severity] ?? severity;
}

function buildLocationLine(
  finding: FindingDetailFinding,
  report: Partial<VulnerabilityReportDetails> | null,
): string {
  const path = report?.affectedFilePath || finding.filePath || "";
  if (!path) return "";
  const line = finding.startLine ?? report?.exactLineNumber ?? null;
  let suffix = "";
  if (line != null) {
    suffix = `:${line}`;
    if (
      finding.endLine != null &&
      finding.startLine != null &&
      finding.endLine !== finding.startLine
    ) {
      suffix += `-${finding.endLine}`;
    }
  }
  return `${path}${suffix}`;
}

function formatCodeBlockWithLineNumbers(
  raw: string,
  startLine?: number | null,
): string {
  const lines = raw.split(/\r?\n/);
  if (lines.length && /^\s*\d+:\s?/.test(lines[0] ?? "")) {
    return raw;
  }
  const start = Math.max(1, startLine ?? 1);
  return lines.map((line, i) => `${start + i}: ${line}`).join("\n");
}

function buildWhyVulnerableBullets(
  report: Partial<VulnerabilityReportDetails> | null,
): string[] {
  const out: string[] = [];
  if (report?.lineByLineExplanation?.length) {
    for (const line of report.lineByLineExplanation) {
      const label =
        line.lineNumber != null ? `Line ${line.lineNumber}` : "Reference";
      out.push(`${label}: ${line.explanation}`);
    }
  }
  if (report?.rootCause) {
    const parts = report.rootCause
      .split(/\n+/)
      .map((s) => s.trim())
      .filter(Boolean);
    for (const p of parts) {
      if (out.length >= 10) break;
      if (!out.some((x) => x.includes(p.slice(0, 48)))) out.push(p);
    }
  }
  return out.slice(0, 12);
}

function FindingReportCodeBlock({
  code,
  maxHeight = "min(24rem, 55vh)",
}: {
  code: string;
  maxHeight?: string;
}) {
  const copy = () => {
    void navigator.clipboard.writeText(code);
    toast.success("Copied to clipboard");
  };
  return (
    <div className="relative min-w-0 max-w-full">
      <Button
        type="button"
        variant="secondary"
        size="sm"
        className="absolute right-3 top-3 z-10 h-8 gap-1 text-xs shadow-md"
        onClick={copy}
      >
        <Copy className="h-3.5 w-3.5 shrink-0" aria-hidden />
        Copy
      </Button>
      <pre className="code-block m-0 min-w-0 pt-12" style={{ maxHeight }}>
        <code className="block min-w-0 whitespace-pre-wrap break-words">
          {code}
        </code>
      </pre>
    </div>
  );
}

function renderSecurityTestsContent(raw: unknown): ReactNode {
  const t = normalizeCustomerFacingText(raw).trim();
  if (!t) return null;
  const codeLike =
    /^\s*(curl|wget|\$ |#!\/|import |export |const |function |def |class |describe\(|it\(|expect\()/im.test(
      t,
    ) || (t.includes("{") && t.includes("}") && t.length > 120);
  if (codeLike) {
    return (
      <FindingReportCodeBlock code={t} maxHeight="min(22rem, 50vh)" />
    );
  }
  const lines = t.split(/\n/).map((l) => l.trim()).filter(Boolean);
  const items: string[] = [];
  for (const line of lines) {
    const b = line.match(/^[-*•]\s*(.+)$/);
    const n = line.match(/^\d+[.)]\s*(.+)$/);
    if (b) items.push(b[1]);
    else if (n) items.push(n[1]);
    else items.push(line);
  }
  return (
    <ul className="space-y-2">
      {items.map((item, i) => (
        <li
          key={i}
          className="report-paragraph flex min-w-0 gap-2 text-sm text-muted-foreground"
        >
          <span
            className="mt-2 h-1 w-1 shrink-0 rounded-full bg-primary"
            aria-hidden
          />
          <span className="min-w-0 flex-1 break-words [overflow-wrap:anywhere]">
            {item}
          </span>
        </li>
      ))}
    </ul>
  );
}

function ReportSection({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon?: LucideIcon;
  children: ReactNode;
}) {
  return (
    <section className="report-section">
      <header className="report-section-header flex min-w-0 items-center gap-2">
        {Icon ? (
          <Icon className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        ) : null}
        <span className="min-w-0 flex-1 break-words">{title}</span>
      </header>
      <div className="section-content min-w-0">{children}</div>
    </section>
  );
}

function formatPreconditionLabel(key: string): string {
  const k = key.replace(/\s+/g, "").toLowerCase();
  if (k.includes("chain")) return "Chainability";
  if (k === "privilegesrequired" || k.includes("privileges"))
    return "Privileges required";
  if (k.includes("authentication")) return "Authentication required";
  if (k.includes("userinteraction")) return "User interaction required";
  if (k.includes("privilegeescalation"))
    return "Privilege escalation potential";
  if (k.includes("sensitive")) return "Sensitive data exposure";
  return key.replace(/([A-Z])/g, " $1").trim();
}

// ─── Component ───────────────────────────────────────────────────────

export function FindingDetailContent({
  finding,
  onStatusChange,
  onCollapse,
}: FindingDetailContentProps) {
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
      onStatusChange?.();
    } catch {
      toast.error("Failed to update finding status");
    }
  };

  const report = getReportDetails(finding);

  const descParts = finding.description.split(/\nRecommendation:\s*/i);
  const mainDescription = normalizeCustomerFacingText(descParts[0]);
  const embeddedRecommendation = descParts[1]
    ? normalizeCustomerFacingText(descParts[1])
    : undefined;

  const confidencePercent = finding.confidence
    ? finding.confidence <= 1
      ? Math.round(finding.confidence * 100)
      : Math.round(finding.confidence)
    : null;

  const displayTitle = report?.vulnerabilityName?.trim() || finding.title;
  const locationLine = buildLocationLine(finding, report);
  const vulnCode =
    report?.vulnerableSourceCode?.trim() || finding.snippet?.trim() || "";

  const statusLabel =
    FINDING_STATUSES.find((s) => s.value === (finding.status || "OPEN"))
      ?.label ?? (finding.status || "Open");

  const filePathOnly = report?.affectedFilePath || finding.filePath || "";
  const lineNum = finding.startLine ?? report?.exactLineNumber ?? null;
  const displayCode = vulnCode
    ? formatCodeBlockWithLineNumbers(
        vulnCode,
        finding.startLine ?? report?.exactLineNumber,
      )
    : "";
  const whyBullets = buildWhyVulnerableBullets(report);

  const primaryFixExplanation =
    report?.secureFixExplanation?.trim() ||
    embeddedRecommendation?.trim() ||
    "";

  return (
    <div className="sast-report finding-report report-container w-full min-w-0 max-w-full overflow-x-hidden p-1 sm:p-0">
      {/* 1. Finding header card */}
      <div className="finding-card report-container">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 flex-1 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
                {formatSeverityLabel(finding.severity)}
              </span>
            </div>
            <h2 className="text-balance break-words text-xl font-bold leading-tight text-foreground sm:text-2xl">
              {displayTitle}
            </h2>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <div className="min-w-0">
                <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  Status
                </p>
                <div className="mt-1">
                  <Select
                    value={finding.status || "OPEN"}
                    onValueChange={handleStatusChange}
                  >
                    <SelectTrigger className="h-9 w-full max-w-[220px] text-xs">
                      <SelectValue placeholder={statusLabel} />
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
              <div>
                <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  Confidence
                </p>
                <p className="report-paragraph mt-1 text-sm font-semibold tabular-nums">
                  {confidencePercent !== null ? `${confidencePercent}%` : "—"}
                </p>
              </div>
              <div className="min-w-0 sm:col-span-1">
                <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  CWE
                </p>
                <div className="report-paragraph mt-1 flex flex-wrap items-center gap-2 text-sm">
                  {finding.cweId ? (
                    <a
                      href={getCweUrl(finding.cweId)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 break-all font-medium text-primary hover:underline"
                    >
                      {finding.cweId}
                      <ExternalLink className="h-3 w-3 shrink-0" />
                    </a>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </div>
              </div>
            </div>
            {locationLine && (
              <div>
                <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  File / line
                </p>
                <p className="report-paragraph mt-1 font-mono text-sm text-foreground">
                  {locationLine}
                </p>
              </div>
            )}
            {report?.affectedFunction && (
              <div>
                <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  Function / component
                </p>
                <p className="report-paragraph mt-1 font-mono text-sm text-foreground">
                  {report.affectedFunction}
                </p>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {finding.ruleId && (
                <Badge variant="secondary" className="max-w-full font-mono text-xs">
                  {finding.ruleId}
                </Badge>
              )}
              <Badge variant="outline" className="text-xs">
                {SCANNER_LABELS[
                  finding.scanner as keyof typeof SCANNER_LABELS
                ] || finding.scanner}
              </Badge>
            </div>
          </div>
          {onCollapse && (
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
          )}
        </div>
      </div>

      <div className="report-container mt-4 max-h-[min(88vh,1800px)] w-full min-w-0 space-y-5 overflow-x-hidden overflow-y-auto overscroll-contain pb-4">
        {/* 2. Location */}
        {(filePathOnly || displayCode) && (
          <ReportSection title="Location" icon={FileCode}>
            {filePathOnly && (
              <p className="report-paragraph description text-sm text-foreground">
                <span className="font-semibold text-muted-foreground">File: </span>
                <span className="break-all font-mono">{filePathOnly}</span>
              </p>
            )}
            {lineNum != null && (
              <p className="report-paragraph description mt-2 text-sm">
                <span className="font-semibold text-muted-foreground">Line: </span>
                {lineNum}
                {finding.endLine != null &&
                finding.startLine != null &&
                finding.endLine !== finding.startLine
                  ? `–${finding.endLine}`
                  : ""}
              </p>
            )}
            {report?.affectedFunction && (
              <p className="report-paragraph description mt-2 text-sm">
                <span className="font-semibold text-muted-foreground">
                  Function / component:{" "}
                </span>
                <span className="break-all font-mono text-foreground">
                  {report.affectedFunction}
                </span>
              </p>
            )}
            {displayCode ? (
              <div className="mt-4">
                <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Vulnerable code (with line numbers)
                </p>
                <FindingReportCodeBlock code={displayCode} />
              </div>
            ) : null}
          </ReportSection>
        )}

        {/* 3. Description */}
        <ReportSection title="Description" icon={Info}>
          <p className="report-paragraph description text-sm text-muted-foreground">
            {mainDescription}
          </p>
        </ReportSection>

        {report ? (
          <>
            {/* 4. Why this is vulnerable */}
            {whyBullets.length > 0 && (
              <ReportSection title="Why this is vulnerable" icon={AlertTriangle}>
                <ul className="list-disc space-y-2 pl-5 text-sm text-muted-foreground">
                  {whyBullets.map((b, i) => (
                    <li key={i} className="report-paragraph">
                      {b}
                    </li>
                  ))}
                </ul>
              </ReportSection>
            )}

            {/* 5. Attack reasoning */}
            {(report.realWorldAttackScenario ||
              report.advancedAttackerReasoning ||
              report.attackPreconditions) && (
              <ReportSection title="Attack reasoning" icon={Target}>
                <div className="attack-reasoning space-y-4">
                  {report.realWorldAttackScenario && (
                    <div>
                      <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        Real-world attack scenario
                      </h4>
                      <p className="report-paragraph text-sm text-muted-foreground">
                        {report.realWorldAttackScenario}
                      </p>
                    </div>
                  )}
                  {report.advancedAttackerReasoning && (
                    <div>
                      <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        Advanced attack chain
                      </h4>
                      <p className="report-paragraph text-sm text-muted-foreground">
                        {report.advancedAttackerReasoning}
                      </p>
                    </div>
                  )}
                  {report.attackPreconditions &&
                    Object.keys(report.attackPreconditions).length > 0 && (
                      <dl className="space-y-2 border-t border-border/60 pt-3 text-sm">
                        {Object.entries(report.attackPreconditions).map(
                          ([key, value]) => (
                            <div key={key} className="grid gap-1 sm:grid-cols-[minmax(0,200px)_1fr]">
                              <dt className="font-semibold text-foreground">
                                {formatPreconditionLabel(key)}:
                              </dt>
                              <dd className="report-paragraph min-w-0 text-muted-foreground">
                                {value}
                              </dd>
                            </div>
                          ),
                        )}
                      </dl>
                    )}
                </div>
              </ReportSection>
            )}

            {/* 6. Steps to reproduce */}
            {(report.stepsToReproduce?.length ||
              report.proofOfConcept ||
              report.expectedVulnerableBehavior) && (
              <ReportSection title="Steps to reproduce" icon={Target}>
                {report.stepsToReproduce &&
                  report.stepsToReproduce.length > 0 && (
                    <ol className="report-steps mb-4 list-decimal space-y-3 pl-5 text-sm text-muted-foreground">
                      {report.stepsToReproduce.map((step, index) => (
                        <li key={index} className="report-paragraph pl-1">
                          {step}
                        </li>
                      ))}
                    </ol>
                  )}
                {report.proofOfConcept && (
                  <div>
                    <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Commands / payload (authorized testing)
                    </p>
                    <FindingReportCodeBlock code={report.proofOfConcept} />
                  </div>
                )}
                {report.expectedVulnerableBehavior && (
                  <p className="report-paragraph mt-3 text-xs text-muted-foreground">
                    <span className="font-semibold text-foreground">
                      Expected vulnerable behavior:{" "}
                    </span>
                    {report.expectedVulnerableBehavior}
                  </p>
                )}
              </ReportSection>
            )}

            {/* 7. Impact */}
            {report.businessImpact && (
              <ReportSection title="Impact" icon={AlertTriangle}>
                <p className="report-paragraph impact text-sm text-muted-foreground">
                  {report.businessImpact}
                </p>
              </ReportSection>
            )}

            {/* 9. Security tests */}
            {report.securityTests && (
              <ReportSection title="Security tests" icon={Shield}>
                {renderSecurityTestsContent(report.securityTests)}
              </ReportSection>
            )}

            {/* 10. Regression prevention */}
            {report.regressionPrevention && (
              <ReportSection title="Regression prevention" icon={Info}>
                <p className="report-paragraph regression-prevention text-sm text-muted-foreground">
                  {report.regressionPrevention}
                </p>
              </ReportSection>
            )}
          </>
        ) : null}

        {(primaryFixExplanation || report?.secureCodeExample) && (
          <ReportSection title="How to fix" icon={Wrench}>
            {primaryFixExplanation ? (
              <div className="remediation space-y-3">
                <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Immediate remediation & secure design
                </h4>
                <p className="report-paragraph remediation text-sm text-muted-foreground">
                  {primaryFixExplanation}
                </p>
              </div>
            ) : null}
            {report?.secureCodeExample ? (
              <div className="mt-4">
                <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Secure code example
                </p>
                <FindingReportCodeBlock code={report.secureCodeExample} />
              </div>
            ) : null}
          </ReportSection>
        )}
      </div>
    </div>
  );

}

export function FindingDetailPanel({
  finding,
  open,
  onClose,
  onStatusChange,
}: FindingDetailPanelProps) {
  if (!finding) return null;

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="flex h-full w-full min-w-0 max-w-full flex-col overflow-hidden p-0 sm:max-w-2xl">
        <ScrollArea className="min-h-0 min-w-0 flex-1">
          <div className="min-w-0 max-w-full p-4">
            <FindingDetailContent
              finding={finding}
              onStatusChange={() =>
                onStatusChange?.(finding.id, finding.status ?? "OPEN")
              }
            />
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  );
}
