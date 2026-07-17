"use client";

import { useState, useEffect } from "react";
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

function SecretFindingReport({ finding, sourceContext }: { finding: Finding; sourceContext?: FindingScanSourceContext }) {
  const [generatedDetails, setGeneratedDetails] = useState<{
    summary: string;
    vulnerabilityDetails: string;
    stepsToReproduce: string[];
    impact: string;
    remediation: string[];
  } | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  useEffect(() => {
    const metadata = finding.metadata as Record<string, unknown> | undefined;
    const cachedDetails = (metadata?.generatedDetails as typeof generatedDetails | undefined);
    if (cachedDetails) {
      setGeneratedDetails(cachedDetails);
    } else {
      loadGeneratedDetailsForSecret();
    }
  }, [finding.id]);

  const loadGeneratedDetailsForSecret = async () => {
    setLoadingDetails(true);
    try {
      const response = await fetch(
        `/api/findings/${finding.id}/generate-details`,
        { method: "POST" }
      );
      if (response.ok) {
        const details = await response.json();
        setGeneratedDetails(details);
      }
    } catch (error) {
      console.error("Failed to load generated details:", error);
    } finally {
      setLoadingDetails(false);
    }
  };

  const metadata = finding.metadata as Record<string, unknown> | undefined;
  const secretType = typeof metadata?.secretType === "string"
    ? metadata.secretType
    : (finding.title.split(":")[0] || "Secret");
  const report = buildStoredFindingReport(finding);
  const githubUrl = githubCodeUrl(sourceContext, finding);

  return (
    <section className="finding-detail-report surface-card min-w-0 max-w-full space-y-5 overflow-hidden p-4">
      {/* Secrets Identified Card */}
      <ReportBlock title="Secrets Identified" icon={<span className="text-lg">🔐</span>}>
        <div className="space-y-3">
          <p className="text-sm leading-relaxed text-muted-foreground">
            The following secret value was found exposed in the source code.
          </p>
          <div className="rounded-lg border border-border/60 bg-muted/30 p-3 space-y-2">
            <div className="grid grid-cols-3 gap-3">
              <div>
                <p className="text-xs font-medium text-muted-foreground">Secret Type</p>
                <p className="text-sm font-semibold text-foreground">{secretType}</p>
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground">Secret Value</p>
                <p className="text-sm font-mono text-foreground">****</p>
              </div>
              <div>
                <p className="text-xs font-medium text-muted-foreground">Location</p>
                {githubUrl ? (
                  <a
                    href={githubUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-blue-600 hover:underline flex items-center gap-1"
                  >
                    {finding.filePath}
                    {finding.startLine ? `:${finding.startLine}` : ""}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                ) : (
                  <p className="text-sm text-foreground">
                    {finding.filePath}
                    {finding.startLine ? `:${finding.startLine}` : ""}
                  </p>
                )}
              </div>
            </div>
          </div>
          {finding.snippet && (
            <div className="rounded-lg border border-orange-200 bg-orange-50 p-3">
              <p className="text-xs font-medium text-orange-900 mb-1">⚠️ Warning</p>
              <p className="text-xs text-orange-800">
                This secret was found in source code and may have been committed to version control.
              </p>
            </div>
          )}
        </div>
      </ReportBlock>

      {/* Risk Section */}
      <ReportBlock title="Risk" icon={<span className="text-lg">🛡️</span>}>
        {loadingDetails ? (
          <span className="text-muted-foreground italic text-sm">Generating risk analysis...</span>
        ) : (
          <ReportRichText text={generatedDetails?.impact || report.impact} />
        )}
      </ReportBlock>

      {/* Recommendations Section */}
      <ReportBlock title="Recommendations" icon={<span className="text-lg">✅</span>}>
        {loadingDetails ? (
          <span className="text-muted-foreground italic text-sm">Generating recommendations...</span>
        ) : (
          <ReportPlainList items={generatedDetails?.remediation || report.remediation} />
        )}
      </ReportBlock>
    </section>
  );
}

function SastFindingReport({ finding, sourceContext }: { finding: Finding; sourceContext?: FindingScanSourceContext }) {
  const [generatedDetails, setGeneratedDetails] = useState<{
    summary: string;
    vulnerabilityDetails: string;
    stepsToReproduce: string[];
    impact: string;
    remediation: string[];
  } | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  const report = buildStoredFindingReport(finding);
  const metadata = finding.metadata as Record<string, unknown> | undefined;

  // Load AI-generated details on mount
  useEffect(() => {
    const cachedDetails = (metadata?.generatedDetails as typeof generatedDetails | undefined);
    if (cachedDetails) {
      setGeneratedDetails(cachedDetails);
    } else {
      loadGeneratedDetails();
    }
  }, [finding.id]);

  const loadGeneratedDetails = async () => {
    setLoadingDetails(true);
    try {
      const response = await fetch(
        `/api/findings/${finding.id}/generate-details`,
        { method: "POST" }
      );
      if (response.ok) {
        const details = await response.json();
        setGeneratedDetails(details);
      }
    } catch (error) {
      console.error("Failed to load generated details:", error);
    } finally {
      setLoadingDetails(false);
    }
  };

  // Extract title and CWE for heading
  const title = finding.title || report.vulnerabilityName;
  const cwe = finding.cweId ? `(${finding.cweId})` : '';
  const heading = `${title} ${cwe}`.trim();

  // Extract curl command from steps if present
  const stepsToUse = generatedDetails?.stepsToReproduce || report.stepsToReproduce;
  const curlCommand = stepsToUse
    .map(step => {
      const curlMatch = step.match(/curl\s+[^\n]+/i);
      return curlMatch ? curlMatch[0] : null;
    })
    .find(cmd => cmd !== null);

  const handleCopyCurl = () => {
    if (curlCommand) {
      navigator.clipboard.writeText(curlCommand);
      toast.success("Curl command copied to clipboard");
    }
  };

  return (
    <section className="finding-detail-report min-w-0 w-full overflow-hidden p-3 sm:p-4 space-y-3 sm:space-y-4 text-sm sm:text-base">
      {/* Main Heading */}
      <div className="space-y-2 pb-2 border-b border-border/40">
        <h1 className="text-base sm:text-lg font-bold text-foreground break-words">{heading}</h1>
        <div className="flex items-center gap-4">
          {finding.severity && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Severity:</span>
              <SeverityBadge severity={finding.severity} />
            </div>
          )}
          {(() => {
            const conf = (metadata?.confidence as number | undefined) ?? (finding.confidence as number | undefined) ?? 0;
            return conf > 0 ? (
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">Confidence:</span>
                <span className="text-xs font-semibold">{Math.round(conf * 100)}%</span>
              </div>
            ) : null;
          })()}
        </div>
      </div>

      {/* Summary Section */}
      <div className="space-y-2">
        <h2 className="text-xs sm:text-sm font-semibold text-foreground">Summary</h2>
        <p className="text-xs sm:text-sm leading-relaxed text-foreground">
          {loadingDetails ? (
            <span className="text-muted-foreground italic">Generating summary...</span>
          ) : generatedDetails?.summary ? (
            generatedDetails.summary
          ) : (
            (() => {
              const lines = report.summary.split('\n\n');
              const lead = lines[0] || report.summary;
              const cleanLead = lead
                .split('\n')
                .filter(line => !line.match(/^(What is wrong|Where|Why it is exploitable|How to validate|Severity):/))
                .join('\n')
                .trim();
              return cleanLead || report.summary;
            })()
          )}
        </p>
      </div>

      {/* Affected File */}
      <div className="space-y-2 border-t border-border/40 pt-4">
        <h2 className="text-sm font-semibold text-foreground">Affected File</h2>
        <div className="text-xs space-y-2">
          {(() => {
            const fileUrl = sourceContext && finding.filePath && finding.startLine
              ? githubBlobLineUrl({
                  repoUrl: sourceContext?.repoUrl,
                  commitSha: sourceContext?.commitSha,
                  branch: sourceContext?.branch,
                  defaultBranch: sourceContext?.defaultBranch,
                  filePath: finding.filePath,
                  startLine: finding.startLine,
                })
              : null;

            return (
              <div>
                <p className="text-muted-foreground mb-1"><strong>File:</strong></p>
                {fileUrl ? (
                  <a
                    href={fileUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:underline font-mono text-xs flex items-center gap-1 break-all"
                  >
                    {finding.filePath}
                    <ExternalLink className="h-3 w-3 shrink-0" />
                  </a>
                ) : (
                  <code className="bg-muted px-1.5 py-0.5 rounded block break-all text-foreground">
                    {finding.filePath || "Unknown"}
                  </code>
                )}
              </div>
            );
          })()}

          {finding.startLine && (
            <div>
              <p className="text-muted-foreground mb-1"><strong>Location:</strong></p>
              <code className="bg-muted px-1.5 py-0.5 rounded text-foreground">
                Line {finding.startLine}
                {finding.endLine && finding.endLine !== finding.startLine && `-${finding.endLine}`}
              </code>
            </div>
          )}
        </div>
      </div>

      {/* Vulnerability Details */}
      {(generatedDetails?.vulnerabilityDetails || finding.description) && (
        <div className="space-y-2 border-t border-border/40 pt-4">
          <h2 className="text-sm font-semibold text-foreground">Details</h2>
          <p className="text-xs sm:text-sm leading-relaxed text-foreground line-clamp-2">
            {loadingDetails ? (
              <span className="text-muted-foreground italic">Generating details...</span>
            ) : generatedDetails?.vulnerabilityDetails ? (
              generatedDetails.vulnerabilityDetails
            ) : (
              finding.description || "No details available"
            )}
          </p>
        </div>
      )}

      {/* Steps to Reproduce */}
      {finding.scanner !== "K8S" && (generatedDetails?.stepsToReproduce?.length || stepsToUse.length > 0 || loadingDetails) && (
        <div className="space-y-2 border-t border-border/40 pt-4">
          <h2 className="text-sm font-semibold text-foreground">Steps to Reproduce</h2>
          <div className="text-xs sm:text-sm space-y-1.5 text-foreground">
            {loadingDetails ? (
              <span className="text-muted-foreground italic">Generating steps...</span>
            ) : (
              (generatedDetails?.stepsToReproduce || stepsToUse)
                .filter(step => step && step.trim().length > 0)
                .map((step, idx) => (
                  <div key={idx} className="leading-relaxed text-xs">
                    <span className="font-semibold">{idx + 1}.</span> {step}
                  </div>
                ))
            )}
          </div>
        </div>
      )}

      {/* Impact */}
      {(generatedDetails?.impact || report.impact) && (
        <div className="space-y-2 border-t border-border/40 pt-4">
          <h2 className="text-sm font-semibold text-foreground">Impact</h2>
          <p className="text-xs sm:text-sm leading-relaxed text-foreground line-clamp-2">
            {loadingDetails ? (
              <span className="text-muted-foreground italic">Generating impact...</span>
            ) : generatedDetails?.impact ? (
              generatedDetails.impact
            ) : (
              report.impact
            )}
          </p>
        </div>
      )}

      {/* Remediation */}
      {(generatedDetails?.remediation?.length || report.remediation?.length) ? (
        <div className="space-y-2 border-t border-border/40 pt-4">
          <h2 className="text-sm font-semibold text-foreground">Remediation</h2>
          <div className="text-xs sm:text-sm space-y-1.5 text-foreground">
            {loadingDetails ? (
              <span className="text-muted-foreground italic">Generating remediation...</span>
            ) : (
              (generatedDetails?.remediation || report.remediation)
                .filter(step => stripReportMarkdown(step).trim().length > 0)
                .slice(0, 3)
                .map((step, idx) => (
                  <div key={idx} className="leading-relaxed text-xs">
                    <span className="font-semibold">{idx + 1}.</span> {stripReportMarkdown(step)}
                  </div>
                ))
            )}
          </div>
        </div>
      ) : null}
    </section>
  );
}

function MaliciousPkgFindingReport({ finding, sourceContext }: { finding: Finding; sourceContext?: FindingScanSourceContext }) {
  const [generatedDetails, setGeneratedDetails] = useState<{
    summary: string;
    vulnerabilityDetails: string;
    stepsToReproduce: string[];
    impact: string;
    remediation: string[];
  } | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  useEffect(() => {
    const metadata = finding.metadata as Record<string, unknown> | undefined;
    const cachedDetails = (metadata?.generatedDetails as typeof generatedDetails | undefined);
    if (cachedDetails) {
      setGeneratedDetails(cachedDetails);
    } else {
      loadGeneratedDetailsForMalicious();
    }
  }, [finding.id]);

  const loadGeneratedDetailsForMalicious = async () => {
    setLoadingDetails(true);
    try {
      const response = await fetch(
        `/api/findings/${finding.id}/generate-details`,
        { method: "POST" }
      );
      if (response.ok) {
        const details = await response.json();
        setGeneratedDetails(details);
      }
    } catch (error) {
      console.error("Failed to load generated details:", error);
    } finally {
      setLoadingDetails(false);
    }
  };

  const report = buildStoredFindingReport(finding);
  const metadata = finding.metadata as Record<string, unknown> | undefined;
  const vulnData = metadata?.aiAnalysis as { description?: string; impact?: string; remediation?: string[] } | undefined;

  return (
    <section className="finding-detail-report min-w-0 max-w-full overflow-hidden">
      <div className="grid grid-cols-4 gap-3 p-4">
        {/* LEFT COLUMN - Package Info */}
        <div className="space-y-3">
          <div className="surface-card rounded-lg p-3 space-y-2">
            <h3 className="font-semibold text-xs flex items-center gap-2">
              <span>⚠️</span> Package Details
            </h3>
            <div className="space-y-2 text-xs">
              <div>
                <p className="text-xs font-medium text-muted-foreground">Package Name</p>
                <code className="text-xs font-mono text-foreground mt-1 block break-all">{finding.ruleId || "Unknown"}</code>
              </div>
              {finding.filePath && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Found In</p>
                  {sourceContext && githubCodeUrl(sourceContext, finding) ? (
                    <a
                      href={githubCodeUrl(sourceContext, finding) || "#"}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline text-xs flex items-center gap-1 mt-1 break-all"
                    >
                      {finding.filePath}
                      {finding.startLine && <span className="font-semibold">:{finding.startLine}</span>}
                      <ExternalLink className="h-3 w-3 shrink-0" />
                    </a>
                  ) : (
                    <code className="text-xs font-mono text-foreground mt-1 block break-all">
                      {finding.filePath}
                      {finding.startLine && <span className="font-semibold">:{finding.startLine}</span>}
                    </code>
                  )}
                </div>
              )}
              {finding.severity && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Severity</p>
                  <Badge className="mt-1 bg-red-950 text-red-400 dark:bg-red-900 dark:text-red-300 text-xs border border-red-500/30">{finding.severity}</Badge>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* MIDDLE COLUMN - Threat Details */}
        <div className="space-y-3 col-span-2">
          <div className="surface-card rounded-lg p-3">
            <h3 className="font-semibold text-xs flex items-center gap-2 mb-2">
              <span>🚨</span> What's the Threat?
            </h3>
            <div className="space-y-2 text-xs">
              {vulnData?.description ? (
                <p className="text-foreground leading-relaxed">
                  <ReportRichText text={vulnData.description} />
                </p>
              ) : (
                <div className="space-y-2">
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Threat</p>
                    <p className="text-foreground leading-relaxed">
                      {stripReportMarkdown(report.vulnerabilityName || "")}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Details</p>
                    <p className="text-foreground leading-relaxed whitespace-pre-wrap break-words">
                      {stripReportMarkdown(stripGeneratedSections(finding.description) || report.summary)}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {finding.snippet && (
            <div className="surface-card rounded-lg p-3">
              <h3 className="font-semibold text-xs flex items-center gap-2 mb-2">
                <span>📋</span> Detection Evidence
              </h3>
              <pre className="bg-muted/50 p-2 rounded text-xs font-mono overflow-x-auto max-h-32 border border-border/60">
                {finding.snippet}
              </pre>
            </div>
          )}
        </div>

        {/* RIGHT COLUMN - Risk & Action */}
        <div className="space-y-3">
          <div className="surface-card rounded-lg p-3">
            <h3 className="font-semibold text-xs flex items-center gap-2 mb-2">
              <span>📊</span> Impact
            </h3>
            <div className="space-y-2 text-xs text-foreground leading-relaxed">
              {vulnData?.impact ? (
                <p>{vulnData.impact}</p>
              ) : (
                <ReportRichText text={report.impact || "This malicious package poses a critical security risk."} />
              )}
            </div>
          </div>

          <div className="space-y-2">
            <div className="rounded-lg border border-red-500/30 bg-red-950/20 dark:bg-red-950/40 p-2">
              <h3 className="font-semibold text-xs text-red-500 dark:text-red-400 mb-1">🔴 CRITICAL</h3>
              <p className="text-xs text-red-600 dark:text-red-300 leading-tight">
                Remove immediately
              </p>
            </div>

            <div className="rounded-lg border border-orange-500/30 bg-orange-950/20 dark:bg-orange-950/40 p-2">
              <h3 className="font-semibold text-xs text-orange-500 dark:text-orange-400 mb-1">⚡ Action</h3>
              <p className="text-xs text-orange-600 dark:text-orange-300 leading-tight">
                Remove dependency now
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Remediation - Full Width */}
      <div className="border-t border-border/40 p-4">
        <h3 className="font-semibold text-sm flex items-center gap-2 mb-3">
          <span>🔒</span> How to Remove
        </h3>

        <div className="rounded-lg border border-red-500/30 bg-red-950/20 dark:bg-red-950/40 p-3 mb-3">
          <p className="text-xs font-semibold text-red-500 dark:text-red-400 mb-2">Removal Command</p>
          <pre className="bg-background border border-border/60 p-2 rounded text-xs font-mono overflow-x-auto text-foreground">
            npm uninstall {finding.ruleId}
          </pre>
        </div>

        <div className="space-y-2">
          <p className="text-xs font-semibold text-muted-foreground">Steps</p>
          {vulnData?.remediation && vulnData.remediation.length > 0 ? (
            <ol className="space-y-1 list-decimal pl-5 text-xs text-muted-foreground">
              {vulnData.remediation.map((step, i) => (
                <li key={i} className="leading-tight">
                  {step}
                </li>
              ))}
            </ol>
          ) : (
            <ol className="space-y-1 list-decimal pl-5 text-xs text-muted-foreground">
              {report.remediation.slice(0, 4).map((step, i) => (
                <li key={i} className="leading-tight">
                  {stripReportMarkdown(step).substring(0, 70)}...
                </li>
              ))}
            </ol>
          )}
        </div>

        <div className="rounded-lg border border-blue-500/30 bg-blue-950/20 dark:bg-blue-950/40 p-3 mt-3">
          <p className="text-xs font-semibold text-blue-500 dark:text-blue-400 mb-1">⚠️ After Removal</p>
          <ul className="space-y-1 text-xs text-blue-600 dark:text-blue-300">
            <li>• Audit your project: <code className="bg-blue-100 px-1 rounded">npm audit</code></li>
            <li>• Run tests to ensure stability</li>
            <li>• Check commit history for compromises</li>
            <li>• Update credentials if exposed</li>
          </ul>
        </div>
      </div>
    </section>
  );
}

function ScaFindingReport({ finding, sourceContext }: { finding: Finding; sourceContext?: FindingScanSourceContext }) {
  const [generatedDetails, setGeneratedDetails] = useState<{
    summary: string;
    vulnerabilityDetails: string;
    stepsToReproduce: string[];
    impact: string;
    remediation: string[];
  } | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  useEffect(() => {
    const metadata = finding.metadata as Record<string, unknown> | undefined;
    const cachedDetails = (metadata?.generatedDetails as typeof generatedDetails | undefined);
    if (cachedDetails) {
      setGeneratedDetails(cachedDetails);
    } else {
      loadGeneratedDetailsForSca();
    }
  }, [finding.id]);

  const loadGeneratedDetailsForSca = async () => {
    setLoadingDetails(true);
    try {
      const response = await fetch(
        `/api/findings/${finding.id}/generate-details`,
        { method: "POST" }
      );
      if (response.ok) {
        const details = await response.json();
        setGeneratedDetails(details);
      }
    } catch (error) {
      console.error("Failed to load generated details:", error);
    } finally {
      setLoadingDetails(false);
    }
  };

  const report = buildStoredFindingReport(finding);
  const metadata = finding.metadata as Record<string, unknown> | undefined;
  const fixVersion = typeof metadata?.fixVersion === "string" ? metadata.fixVersion : undefined;
  const currentVersion = typeof metadata?.currentVersion === "string" ? metadata.currentVersion : undefined;
  const cveId = finding.cveId || (Array.isArray(metadata?.cves) ? metadata.cves[0] : undefined);

  // Get AI-analyzed vulnerability data from finding metadata (analyzed during scan)
  const vulnData = metadata?.aiAnalysis as { description?: string; impact?: string; remediation?: string[] } | undefined;

  return (
    <section className="finding-detail-report min-w-0 max-w-full overflow-hidden">
      <div className="grid grid-cols-4 gap-3 p-4">
        {/* LEFT COLUMN - Dependency Info */}
        <div className="space-y-3">
          <div className="surface-card rounded-lg p-3 space-y-2">
            <h3 className="font-semibold text-xs flex items-center gap-2">
              <span>📦</span> Dependency Details
            </h3>
            <div className="space-y-2 text-xs">
              <div>
                <p className="text-xs font-medium text-muted-foreground">Package Name</p>
                <code className="text-sm font-mono text-foreground mt-1 block break-all">{finding.ruleId || "Unknown"}</code>
              </div>
              {currentVersion && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Current Version</p>
                  <p className="text-foreground font-semibold mt-1">{currentVersion}</p>
                </div>
              )}
              {fixVersion && (
                <div className="rounded-lg bg-green-50 dark:bg-green-900/20 p-2">
                  <p className="text-xs font-medium text-green-800 dark:text-green-300">Fix Available</p>
                  <p className="text-sm font-semibold text-green-700 dark:text-green-400 mt-1">{fixVersion}</p>
                </div>
              )}
              {finding.filePath && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Found In</p>
                  {sourceContext && githubCodeUrl(sourceContext, finding) ? (
                    <a
                      href={githubCodeUrl(sourceContext, finding) || "#"}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline text-sm flex items-center gap-1 mt-1 break-all"
                    >
                      {finding.filePath}
                      {finding.startLine && <span className="font-semibold">:{finding.startLine}</span>}
                      <ExternalLink className="h-3 w-3 shrink-0" />
                    </a>
                  ) : (
                    <code className="text-sm font-mono text-foreground mt-1 block break-all">
                      {finding.filePath}
                      {finding.startLine && <span className="font-semibold">:{finding.startLine}</span>}
                    </code>
                  )}
                </div>
              )}
              {finding.severity && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Severity</p>
                  <Badge className="mt-1 bg-red-100 text-red-800">{finding.severity}</Badge>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* MIDDLE COLUMN - Vulnerability Details */}
        <div className="space-y-3 col-span-2">
          {/* What's the issue - DETAILED */}
          <div className="surface-card rounded-lg p-3">
            <h3 className="font-semibold text-xs flex items-center gap-2 mb-2">
              <span>⚠️</span> What's the Issue?
            </h3>
            <div className="space-y-2 text-xs">
              {vulnData?.description ? (
                <div className="text-foreground leading-relaxed">
                  <ReportRichText text={vulnData.description} />
                </div>
              ) : (
                <div className="space-y-3">
                  {/* Extract detailed issue from report */}
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Vulnerability</p>
                    <p className="text-foreground leading-relaxed">
                      {stripReportMarkdown(report.vulnerabilityName || "")}
                    </p>
                  </div>

                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Description</p>
                    <p className="text-foreground leading-relaxed whitespace-pre-wrap break-words">
                      {stripReportMarkdown(stripGeneratedSections(finding.description) || report.summary)}
                    </p>
                  </div>

                  {/* Extract Why It's Exploitable */}
                  {report.summary.includes("Why it is exploitable") && (
                    <div>
                      <p className="text-xs font-semibold text-muted-foreground mb-1">Why It's Exploitable</p>
                      <p className="text-foreground leading-relaxed whitespace-pre-wrap break-words">
                        {stripReportMarkdown(
                          report.summary
                            .split("Why it is exploitable:")[1]
                            ?.split("\n\n")[0]
                            ?.trim() || ""
                        )}
                      </p>
                    </div>
                  )}

                  {/* Attack Vector */}
                  {report.stepsToReproduce.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-muted-foreground mb-1">Attack Vector</p>
                      <ol className="space-y-1 list-decimal pl-5 text-foreground leading-relaxed">
                        {report.stepsToReproduce.slice(0, 3).map((step, i) => (
                          <li key={i} className="text-xs">
                            {stripReportMarkdown(step)}
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}
                </div>
              )}

              {/* CVE & References */}
              <div className="space-y-2">
                {cveId && (
                  <div className="rounded-lg border border-border/60 bg-muted/30 p-2">
                    <p className="text-xs font-medium text-muted-foreground">CVE Reference</p>
                    <a
                      href={getCveUrl(cveId)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline text-sm flex items-center gap-1 mt-1"
                    >
                      {cveId}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                )}
                {finding.ruleId && (
                  <div className="rounded-lg border border-border/60 bg-muted/30 p-2">
                    <p className="text-xs font-medium text-muted-foreground">CWE/Reference</p>
                    <code className="text-xs font-mono text-foreground">{finding.ruleId}</code>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Code Evidence - DETAILED */}
          {finding.snippet && (
            <div className="surface-card rounded-lg p-3">
              <h3 className="font-semibold text-xs flex items-center gap-2 mb-2">
                <span>🔍</span> Where It's Used
              </h3>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground">
                  Location:
                </p>
                {finding.filePath && (
                  <div className="rounded-lg bg-muted/30 p-2 border border-border/60">
                    <p className="text-xs font-mono text-foreground break-all">
                      {finding.filePath}
                      {finding.startLine && <span className="font-semibold">:{finding.startLine}</span>}
                    </p>
                  </div>
                )}
                <pre className="bg-muted/50 p-2 rounded text-xs font-mono overflow-x-auto max-h-32 border border-border/60">
                  {finding.snippet}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* RIGHT COLUMN - Impact & Fix */}
        <div className="space-y-3">
          {/* Business Impact - DETAILED */}
          <div className="surface-card rounded-lg p-3">
            <h3 className="font-semibold text-xs flex items-center gap-2 mb-2">
              <span>📊</span> Impact
            </h3>
            <div className="space-y-2 text-xs text-foreground leading-relaxed">
              {vulnData?.impact ? (
                <p>{vulnData.impact}</p>
              ) : (
                <>
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Risk Summary</p>
                    <ReportRichText text={report.impact || "This vulnerable dependency poses a security risk to your application and users."} />
                  </div>

                  {/* Detailed consequences */}
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Potential Consequences</p>
                    <ul className="space-y-1 list-disc pl-4 text-muted-foreground">
                      <li className="text-xs">Unauthorized data access or data breach</li>
                      <li className="text-xs">Application downtime or service disruption</li>
                      <li className="text-xs">Performance degradation and system slowdown</li>
                      <li className="text-xs">Legal/compliance violations (GDPR, SOC 2, etc.)</li>
                      <li className="text-xs">Reputation damage and customer trust loss</li>
                    </ul>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Severity & Risk */}
          <div className="space-y-2">
            <div className="rounded-lg border border-red-200 bg-red-50 p-2">
              <h3 className="font-semibold text-xs text-red-900 mb-1">🔴 {finding.severity || "HIGH"}</h3>
              <p className="text-xs text-red-800 leading-tight">
                Known vulnerability. Exploit is likely.
              </p>
            </div>

            <div className="rounded-lg border border-green-200 bg-green-50 p-2">
              <h3 className="font-semibold text-xs text-green-900 mb-1">✓ Fix Available</h3>
              <p className="text-xs text-green-800 leading-tight font-mono">
                {fixVersion ? `v${fixVersion}` : "Latest"}
              </p>
            </div>
          </div>

          {/* Quick Fix */}
          {fixVersion && (
            <div className="rounded-lg border border-green-200 bg-green-50 p-4">
              <h3 className="font-semibold text-sm text-green-900 mb-2">✓ Quick Fix Available</h3>
              <p className="text-xs text-green-800 mb-2">Upgrade to version {fixVersion}</p>
              <code className="text-xs font-mono bg-green-100 px-2 py-1 rounded block">
                npm install {finding.ruleId}@{fixVersion}
              </code>
            </div>
          )}
        </div>
      </div>

      {/* Remediation - Full Width DETAILED */}
      <div className="border-t border-border/40 p-4">
        <h3 className="font-semibold text-sm flex items-center gap-2 mb-3">
          <span>🔧</span> How to Fix
        </h3>

        {/* Fix Instructions */}
        {fixVersion && (
          <div className="rounded-lg border border-green-200 bg-green-50 p-3 mb-3">
            <p className="text-xs font-semibold text-green-900 mb-2">Upgrade Command</p>
            <pre className="bg-white p-2 rounded border border-green-200 text-xs font-mono overflow-x-auto">
              npm install {finding.ruleId}@{fixVersion}
            </pre>
          </div>
        )}

        {/* Remediation steps */}
        <div className="space-y-2">
          <p className="text-xs font-semibold text-muted-foreground">Steps</p>
          {vulnData?.remediation && vulnData.remediation.length > 0 ? (
            <ol className="space-y-1 list-decimal pl-5 text-xs text-muted-foreground">
              {vulnData.remediation.map((step, i) => (
                <li key={i} className="leading-tight">
                  {step.split("\n")[0]}
                </li>
              ))}
            </ol>
          ) : (
            <ol className="space-y-1 list-decimal pl-5 text-xs text-muted-foreground">
              {report.remediation.slice(0, 3).map((step, i) => (
                <li key={i} className="leading-tight">
                  {stripReportMarkdown(step).substring(0, 60)}...
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </section>
  );
}

function IacFindingReport({
  finding,
  scanId,
  sourceContext,
}: {
  finding: Finding;
  scanId: string;
  sourceContext?: FindingScanSourceContext;
}) {
  const [generatedDetails, setGeneratedDetails] = useState<{
    summary: string;
    vulnerabilityDetails: string;
    stepsToReproduce: string[];
    impact: string;
    remediation: string[];
  } | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);

  useEffect(() => {
    const metadata = finding.metadata as Record<string, unknown> | undefined;
    const cachedDetails = (metadata?.generatedDetails as typeof generatedDetails | undefined);
    if (cachedDetails) {
      setGeneratedDetails(cachedDetails);
    } else {
      loadGeneratedDetailsForIac();
    }
  }, [finding.id]);

  const loadGeneratedDetailsForIac = async () => {
    setLoadingDetails(true);
    try {
      const response = await fetch(
        `/api/findings/${finding.id}/generate-details`,
        { method: "POST" }
      );
      if (response.ok) {
        const details = await response.json();
        setGeneratedDetails(details);
      }
    } catch (error) {
      console.error("Failed to load generated details:", error);
    } finally {
      setLoadingDetails(false);
    }
  };

  const report = buildStoredFindingReport(finding);
  const metadata = finding.metadata as Record<string, unknown> | undefined;

  // Get AI-analyzed data from finding metadata (analyzed during scan)
  const data = metadata?.aiAnalysis as {
    summary?: string;
    developerFix?: string;
    verificationSteps?: string[];
    optionalUnifiedDiff?: string | null;
  } | null;

  return (
    <section className="finding-detail-report min-w-0 max-w-full overflow-hidden">
      <div className="grid grid-cols-4 gap-3 p-4">
        {/* LEFT COLUMN - Resource Info */}
        <div className="space-y-3">
          <div className="surface-card rounded-lg p-3 space-y-2">
            <h3 className="font-semibold text-xs flex items-center gap-2">
              <span>🏗️</span> Resource
            </h3>
            <div className="space-y-2 text-xs">
              {finding.filePath && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">File</p>
                  {sourceContext && githubCodeUrl(sourceContext, finding) ? (
                    <a
                      href={githubCodeUrl(sourceContext, finding) || "#"}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline text-xs flex items-center gap-1 mt-1 break-all"
                    >
                      {finding.filePath}
                      {finding.startLine && <span className="font-semibold">:{finding.startLine}</span>}
                      <ExternalLink className="h-3 w-3 shrink-0" />
                    </a>
                  ) : (
                    <code className="text-xs font-mono text-foreground mt-1 block break-all">
                      {finding.filePath}
                      {finding.startLine && <span className="font-semibold">:{finding.startLine}</span>}
                    </code>
                  )}
                </div>
              )}
              {finding.ruleId && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Rule/Check</p>
                  <code className="text-xs font-mono text-foreground mt-1 block">{finding.ruleId}</code>
                </div>
              )}
              {finding.severity && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Severity</p>
                  <Badge className="mt-1 bg-red-950 text-red-400 dark:bg-red-900 dark:text-red-300 text-xs border border-red-500/30">{finding.severity}</Badge>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* MIDDLE COLUMN - Problem Details */}
        <div className="space-y-3 col-span-2">
          <div className="surface-card rounded-lg p-3">
            <h3 className="font-semibold text-xs flex items-center gap-2 mb-2">
              <span>⚠️</span> What's the Problem?
            </h3>
            <div className="space-y-2 text-xs">
              {data?.summary ? (
                <p className="text-foreground leading-relaxed">
                  <ReportRichText text={data.summary} />
                </p>
              ) : (
                <div className="space-y-2">
                  <p className="text-foreground leading-relaxed">
                    {stripReportMarkdown(report.summary.split("\n\n")[0] || "Infrastructure misconfiguration detected")}
                  </p>
                </div>
              )}
            </div>
          </div>

          {finding.snippet && (
            <div className="surface-card rounded-lg p-3">
              <h3 className="font-semibold text-xs flex items-center gap-2 mb-2">
                <span>📝</span> Configuration
              </h3>
              <pre className="bg-muted/50 p-2 rounded text-xs font-mono overflow-x-auto max-h-32 border border-border/60">
                {finding.snippet}
              </pre>
            </div>
          )}
        </div>

        {/* RIGHT COLUMN - Impact & Fix */}
        <div className="space-y-3">
          <div className="surface-card rounded-lg p-3">
            <h3 className="font-semibold text-xs flex items-center gap-2 mb-2">
              <span>📊</span> Impact
            </h3>
            <div className="space-y-2 text-xs text-foreground leading-relaxed">
              {data ? (
                <ReportRichText text={report.impact} />
              ) : (
                <p className="text-muted-foreground">{report.impact || "This misconfig poses security and operational risks."}</p>
              )}
            </div>
          </div>

          <div className="space-y-2">
            <div className="rounded-lg border border-red-500/30 bg-red-950/20 dark:bg-red-950/40 p-2">
              <h3 className="font-semibold text-xs text-red-500 dark:text-red-400 mb-1">🔴 {finding.severity || "HIGH"}</h3>
              <p className="text-xs text-red-600 dark:text-red-300 leading-tight">
                Fix required
              </p>
            </div>

            <div className="rounded-lg border border-blue-500/30 bg-blue-950/20 dark:bg-blue-950/40 p-2">
              <h3 className="font-semibold text-xs text-blue-500 dark:text-blue-400 mb-1">✓ AI Fix Ready</h3>
              <p className="text-xs text-blue-600 dark:text-blue-300 leading-tight">
                See below
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Solution - Full Width */}
      <div className="border-t border-border/40 p-4 space-y-3">
        <h3 className="font-semibold text-sm flex items-center gap-2">
          <span>🔧</span> How to Fix
        </h3>

        {/* What to change */}
        {data?.developerFix ? (
          <div className="surface-card rounded-lg p-3">
            <p className="text-xs font-semibold text-muted-foreground mb-2">Changes Required</p>
            <div className="text-xs text-foreground leading-relaxed">
              <ReportRichText text={data.developerFix} />
            </div>
          </div>
        ) : (
          <div className="surface-card rounded-lg p-3">
            <p className="text-xs font-semibold text-muted-foreground mb-2">Remediation</p>
            <ol className="space-y-1 list-decimal pl-5 text-xs text-muted-foreground">
              {report.remediation.slice(0, 3).map((step, i) => (
                <li key={i} className="leading-tight">
                  {stripReportMarkdown(step).substring(0, 70)}...
                </li>
              ))}
            </ol>
          </div>
        )}

        {/* Verification steps */}
        {data?.verificationSteps && data.verificationSteps.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-semibold text-muted-foreground">Validation</p>
            <ol className="space-y-1 list-decimal pl-5 text-xs text-muted-foreground">
              {data.verificationSteps.slice(0, 4).map((step, i) => (
                <li key={i} className="leading-tight">
                  {stripReportMarkdown(step).substring(0, 80)}...
                </li>
              ))}
            </ol>
          </div>
        )}

        {/* Suggested patch */}
        {data?.optionalUnifiedDiff && (
          <div className="rounded-lg border border-green-500/30 bg-green-950/20 dark:bg-green-950/40 p-3">
            <p className="text-xs font-semibold text-green-500 dark:text-green-400 mb-2">Suggested Patch</p>
            <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded border border-border/60 bg-background p-2 text-xs font-mono text-foreground">
              {data.optionalUnifiedDiff}
            </pre>
          </div>
        )}
      </div>
    </section>
  );
}

function PatternMatchReport({ finding }: { finding: Finding }) {
  const body = stripGeneratedSections(finding.description);
  return (
    <section className="finding-detail-report surface-card min-w-0 max-w-full space-y-4 overflow-hidden border-border/60 bg-muted/30 p-4">
      <p className="text-sm leading-relaxed text-muted-foreground">
        This match comes from a <strong className="text-foreground">pattern-based</strong>{" "}
        rule. Treat it as a quick signal: confirm in code, then use an{" "}
        <strong className="text-foreground">AI-assisted scan</strong> on the same project for
        a full narrative, curl-style repro hints where possible, and{" "}
        <strong className="text-foreground">Suggest AI fix</strong>.
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
    <ol className="space-y-3 list-none">
      {items.map((step, index) => (
        <li key={index} className="flex gap-3">
          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-xs font-bold text-primary shrink-0">
            {index + 1}
          </span>
          <div className="pt-0.5 min-w-0">
            <ReportRichText text={step} />
          </div>
        </li>
      ))}
    </ol>
  );
}

function FindingMetadataGrid({ finding }: { finding: Finding }) {
  const metadata = finding.metadata as Record<string, unknown> | undefined;
  const details: Array<{ label: string; value: string | React.ReactNode }> = [];

  if (finding.filePath) {
    details.push({ label: "File", value: finding.filePath });
  }

  if (finding.scanner === "K8S") {
    const resourceType = metadata?.resourceType ? String(metadata.resourceType) : undefined;
    const resourceName = metadata?.resourceName ? String(metadata.resourceName) : undefined;
    const namespace = metadata?.namespace ? String(metadata.namespace) : undefined;

    if (resourceType) {
      details.push({ label: "Resource Type", value: resourceType });
    }

    if (resourceName) {
      details.push({ label: "Resource Name", value: resourceName });
    }

    if (namespace) {
      details.push({ label: "Namespace", value: namespace });
    }
  }

  if (metadata?.endpoint) {
    details.push({ label: "Endpoint", value: String(metadata.endpoint) });
  }

  if (finding.severity) {
    details.push({ label: "Severity", value: finding.severity });
  }

  if (metadata?.category || metadata?.vulnerabilityClass) {
    details.push({
      label: "Category",
      value: String(metadata.category || metadata.vulnerabilityClass),
    });
  }

  if (finding.ruleId) {
    details.push({ label: "Rule ID", value: finding.ruleId });
  }

  if (metadata?.cweCategory || metadata?.weaknessClass) {
    details.push({
      label: "Weakness Class",
      value: String(metadata.cweCategory || metadata.weaknessClass),
    });
  }

  // Add usage locations for SCA findings
  const usageLocations = metadata?.usageLocations as Array<{ filePath: string; line: number; usage: string }> | undefined;

  if (details.length === 0 && !usageLocations?.length) return null;

  return (
    <div className="space-y-4">
      {details.length > 0 && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
          {details.map((detail, idx) => (
            <div
              key={idx}
              className="rounded-lg border border-border/60 bg-muted/30 p-3"
            >
              <p className="text-xs font-medium text-muted-foreground">{detail.label}</p>
              <p className="mt-1 break-words text-sm font-semibold text-foreground">
                {detail.value}
              </p>
            </div>
          ))}
        </div>
      )}

      {usageLocations && usageLocations.length > 0 && (
        <div className="rounded-lg border border-border/60 bg-muted/30 p-4">
          <p className="text-xs font-medium text-muted-foreground mb-3">WHERE USED IN SOURCE CODE</p>
          <div className="space-y-2">
            {usageLocations.map((loc, idx) => (
              <div key={idx} className="text-xs space-y-1 p-2 bg-background rounded border border-border">
                <div className="text-foreground font-semibold">{loc.filePath}</div>
                <div className="text-muted-foreground">Line {loc.line}</div>
                <div className="text-muted-foreground font-mono text-xs mt-1 break-all">
                  {loc.usage}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

interface AiSuggestFixResponse {
  summary: string;
  developerFix: string;
  verificationSteps: string[];
  optionalUnifiedDiff: string | null;
}

function K8sFindingReport({ finding }: { finding: Finding; sourceContext?: FindingScanSourceContext }) {
  const report = buildStoredFindingReport(finding);

  return (
    <section className="finding-detail-report interactive-card min-w-0 max-w-full space-y-6 overflow-hidden p-4">
      <FindingMetadataGrid finding={finding} />

      <div className="border-t border-border/40 pt-6">
        <h2 className="text-lg font-bold text-foreground mb-4">
          {stripReportMarkdown(report.vulnerabilityName)}
        </h2>

        <div className="space-y-6">
          <ReportBlock title="What is wrong" icon="📋">
            <ReportSummaryText text={report.summary} />
          </ReportBlock>

          {finding.snippet && (
            <ReportBlock title="Evidence" icon="🧩">
              <pre className="overflow-x-auto rounded-md bg-muted px-3 py-2 text-xs whitespace-pre-wrap text-foreground">
                {finding.snippet}
              </pre>
            </ReportBlock>
          )}

          <ReportBlock title="Impact" icon="⚠️">
            <ReportRichText text={report.impact} />
          </ReportBlock>

          <ReportBlock title="Recommended remediation" icon="🔒">
            <ReportPlainList items={report.remediation} />
          </ReportBlock>
        </div>
      </div>
    </section>
  );
}

function FindingReportSections({ finding, sourceContext }: { finding: Finding; sourceContext?: FindingScanSourceContext }) {
  if (isPatternBasedScanner(finding.scanner)) {
    return <PatternMatchReport finding={finding} />;
  }

  const isK8s = finding.scanner === "K8S";
  if (isK8s) {
    return <K8sFindingReport finding={finding} sourceContext={sourceContext} />;
  }

  const isSecret = finding.scanner?.startsWith("SECRETS");
  if (isSecret) {
    return <SecretFindingReport finding={finding} sourceContext={sourceContext} />;
  }

  const isSast = finding.scanner === "SAST_LLM";
  if (isSast) {
    return <SastFindingReport finding={finding} sourceContext={sourceContext} />;
  }

  const isSca = finding.scanner === "SCA";
  if (isSca) {
    return <ScaFindingReport finding={finding} sourceContext={sourceContext} />;
  }

  const isMaliciousPkg = finding.scanner === "MALICIOUS_PKG";
  if (isMaliciousPkg) {
    return <MaliciousPkgFindingReport finding={finding} sourceContext={sourceContext} />;
  }

  const isIac = finding.scanner === "IAC";
  if (isIac && sourceContext?.scanId) {
    return <IacFindingReport finding={finding} scanId={sourceContext.scanId} sourceContext={sourceContext} />;
  }

  const report = buildStoredFindingReport(finding);

  return (
    <section className="finding-detail-report interactive-card min-w-0 max-w-full space-y-6 overflow-hidden p-4">
      <FindingMetadataGrid finding={finding} />

      <div className="border-t border-border/40 pt-6">
        <h2 className="text-lg font-bold text-foreground mb-4">
          {stripReportMarkdown(report.vulnerabilityName)}
        </h2>

        <div className="space-y-6">
          <ReportBlock title="Summary" icon="📋">
            <ReportSummaryText text={report.summary} />
          </ReportBlock>

          {finding.scanner !== "K8S" && report.stepsToReproduce.length > 0 && (
            <ReportBlock title="Steps to Reproduce" icon="🔧">
              <ReportPlainList items={report.stepsToReproduce} />
            </ReportBlock>
          )}

          <ReportBlock title="Impact" icon="⚠️">
            <ReportRichText text={report.impact} />
          </ReportBlock>

          <ReportBlock title="Remediation" icon="🔒">
            <ReportPlainList items={report.remediation} />
          </ReportBlock>
        </div>
      </div>
    </section>
  );
}

function ReportBlock({
  title,
  children,
  icon,
}: {
  title: string;
  children: ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        {icon && <span className="text-lg">{icon}</span>}
        <h3 className="text-base font-bold text-foreground">{title}</h3>
      </div>
      <div className="min-w-0">{children}</div>
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
    <div className="flex min-w-0 w-full flex-wrap gap-2">
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
      ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
      : "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400"
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
                  <p className="text-xs sm:text-sm leading-relaxed text-foreground">
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
      <SheetContent className="w-full max-w-[100vw] overflow-x-hidden flex flex-col p-0 sm:max-w-2xl">
        {/* Header */}
        <div className="sticky top-0 z-10 bg-background border-b px-4 py-4 sm:px-6">
          <SheetHeader className="space-y-3">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={finding.severity} />
              <Badge variant="outline" className="text-xs">
                {SCANNER_LABELS[
                  finding.scanner as keyof typeof SCANNER_LABELS
                ] || finding.scanner}
              </Badge>
            </div>
            <SheetTitle className="text-left text-lg leading-tight break-words">
              {finding.title}
            </SheetTitle>
            <FindingLocationRow finding={finding} sourceContext={sourceContext} />
            {/* Status Control */}
            <div className="flex flex-col gap-3 pt-1 sm:flex-row sm:items-center sm:flex-wrap">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <FindingActionButtons finding={finding} sourceContext={sourceContext} />
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-muted-foreground shrink-0">Status:</span>
                <Select
                  value={finding.status || "OPEN"}
                  onValueChange={handleStatusChange}
                >
                  <SelectTrigger className="h-7 w-full sm:w-[140px] text-xs">
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
            <SheetDescription className="text-left flex items-center gap-2 flex-wrap text-xs">
              {finding.ruleId && (
                <code className="bg-muted px-1.5 py-0.5 rounded break-all">
                  {finding.ruleId}
                </code>
              )}
              {finding.cweId && (
                <a
                  href={getCweUrl(finding.cweId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:underline flex items-center gap-1 shrink-0"
                >
                  {finding.cweId}
                  <ExternalLink className="h-3 w-3 shrink-0" />
                </a>
              )}
              {finding.cveId && (
                <a
                  href={getCveUrl(finding.cveId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:underline flex items-center gap-1 shrink-0"
                >
                  {finding.cveId}
                  <ExternalLink className="h-3 w-3 shrink-0" />
                </a>
              )}
            </SheetDescription>
          </SheetHeader>
        </div>

        <ScrollArea className="flex-1 w-full min-h-0">
          <div className="min-w-0 space-y-5 overflow-hidden px-4 py-5 sm:px-6">
            <FindingReportSections finding={finding} sourceContext={sourceContext} />
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
    <div className="finding-detail-inline min-w-0 w-full max-w-full overflow-hidden rounded-xl border bg-card shadow-sm flex flex-col">
      <div className="min-w-0 border-b px-4 py-4 sm:px-5">
        <div className="flex min-w-0 flex-col gap-4 lg:flex-row lg:items-start lg:gap-6">
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
                  <ExternalLink className="h-3 w-3 shrink-0" />
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
                  <ExternalLink className="h-3 w-3 shrink-0" />
                </a>
              )}
            </div>
            <h3 className="break-words text-lg font-semibold leading-tight">
              {finding.title}
            </h3>
            <FindingLocationRow finding={finding} sourceContext={sourceContext} />
          </div>
          <div className="flex min-w-0 w-full flex-wrap items-center gap-2 lg:w-auto lg:flex-nowrap lg:justify-end lg:shrink-0">
            <div className="min-w-0 flex-1 lg:flex-1 basis-full lg:basis-auto">
              <FindingActionButtons finding={finding} sourceContext={sourceContext} />
            </div>
            <Select
              value={finding.status || "OPEN"}
              onValueChange={handleStatusChange}
            >
              <SelectTrigger className="h-8 w-full min-w-fit lg:w-[140px] text-xs">
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

      <div className="min-w-0 flex-1 overflow-y-auto space-y-5 p-4 sm:p-5">
        <FindingReportSections finding={finding} sourceContext={sourceContext} />
      </div>
    </div>
  );
}
