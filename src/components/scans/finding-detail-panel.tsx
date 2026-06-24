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

function buildReproductionCommand(finding: Finding): string | null {
  const metadata = finding.metadata as Record<string, unknown> | undefined;
  const scanner = finding.scanner || "";
  const filePath = finding.filePath;
  const startLine = finding.startLine ?? 0;

  // SAST_LLM / ZERO_DAY: curl command if route available, fallback to sed
  if (scanner === "SAST_LLM" || scanner === "ZERO_DAY") {
    const route = metadata?.route ? String(metadata.route) : null;
    const method = metadata?.method ? String(metadata.method) : "GET";
    if (route) {
      return `curl -i -sk -X ${method} -H "Authorization: Bearer <TOKEN>" "${route}"`;
    }
    if (filePath) {
      return `sed -n '${startLine},${startLine + 10}p' ${filePath}`;
    }
    return null;
  }

  // SCA: package manager upgrade command
  if (scanner === "SCA") {
    const pkg = metadata?.packageName ? String(metadata.packageName) : null;
    const fix = metadata?.fixVersion ? String(metadata.fixVersion) : "latest";
    const eco = metadata?.ecosystem ? String(metadata.ecosystem) : null;

    if (!pkg) return null;

    const commands: Record<string, string> = {
      npm: `npm install ${pkg}@${fix}`,
      PyPI: `pip install ${pkg}==${fix}`,
      Go: `go get ${pkg}@${fix}`,
      cargo: `cargo update -p ${pkg}`,
      Packagist: `composer require ${pkg}:${fix}`,
      RubyGems: `gem update ${pkg}`,
      Maven: `mvn versions:use-dep-version -Dincludes=${pkg}:${fix}`,
      NuGet: `dotnet add package ${pkg} --version ${fix}`,
    };

    return commands[eco || ""] || `npm install ${pkg}@${fix}`;
  }

  // MALICIOUS_PKG: package manager remove
  if (scanner === "MALICIOUS_PKG") {
    const pkg = metadata?.packageName ? String(metadata.packageName) : null;
    const eco = metadata?.ecosystem ? String(metadata.ecosystem) : null;

    if (!pkg) return null;

    const commands: Record<string, string> = {
      npm: `npm uninstall ${pkg}`,
      PyPI: `pip uninstall ${pkg}`,
      Go: `go mod edit -droprequire=${pkg}`,
      cargo: `cargo remove ${pkg}`,
      Packagist: `composer remove ${pkg}`,
      RubyGems: `gem uninstall ${pkg}`,
      Maven: `mvn dependency:purge-local-repository -DreResolve=false`,
      NuGet: `dotnet remove package ${pkg}`,
    };

    return commands[eco || ""] || `npm uninstall ${pkg}`;
  }

  // SECRETS: sed to location + revoke instruction
  if (scanner.startsWith("SECRETS")) {
    if (!filePath) return null;
    const credentialType = metadata?.credentialType
      ? String(metadata.credentialType)
      : "credential";
    return `sed -n '${startLine},${startLine + 3}p' ${filePath}\n# Action required: revoke ${credentialType} immediately`;
  }

  // IAC: sed to location
  if (scanner === "IAC") {
    if (!filePath) return null;
    return `sed -n '${startLine},${startLine + 10}p' ${filePath}`;
  }

  // CONTAINER: trivy if image available, else sed
  if (scanner === "CONTAINER") {
    const image = metadata?.image ? String(metadata.image) : null;
    if (image) {
      return `trivy image ${image}`;
    }
    if (filePath) {
      return `sed -n '${startLine},${startLine + 5}p' ${filePath}`;
    }
    return null;
  }

  // DAST or others: no reproduction command
  return null;
}

function SecretFindingReport({ finding }: { finding: Finding }) {
  const metadata = finding.metadata as Record<string, unknown> | undefined;
  const secretType = typeof metadata?.secretType === "string"
    ? metadata.secretType
    : (finding.title.split(":")[0] || "Secret");
  const report = buildStoredFindingReport(finding);
  const reproCommand = buildReproductionCommand(finding);

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
                <p className="text-sm text-foreground">
                  {finding.filePath}
                  {finding.startLine ? `:${finding.startLine}` : ""}
                </p>
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

      {/* Location & Revoke Instruction */}
      {reproCommand && (
        <ReportBlock title="How to Locate" icon={<span className="text-lg">📍</span>}>
          <div className="space-y-3">
            <pre className="max-w-full overflow-x-auto rounded-lg border border-border/60 bg-muted/80 p-3 text-xs font-mono leading-relaxed text-foreground">
              {reproCommand}
            </pre>
            <CopyCommandButton command={reproCommand} />
            <div className="rounded-lg border border-red-200 bg-red-50 p-3">
              <p className="text-sm font-semibold text-red-900">⚠️ Action Required</p>
              <p className="text-xs text-red-800 mt-1">
                Immediately revoke {metadata?.credentialType ? String(metadata.credentialType).toLowerCase() : "this credential"} and rotate any access keys or passwords.
              </p>
            </div>
          </div>
        </ReportBlock>
      )}

      {/* Risk Section */}
      <ReportBlock title="Risk" icon={<span className="text-lg">🛡️</span>}>
        <ReportRichText text={report.impact} />
      </ReportBlock>

      {/* Recommendations Section */}
      <ReportBlock title="Recommendations" icon={<span className="text-lg">✅</span>}>
        <ReportPlainList items={report.remediation} />
      </ReportBlock>
    </section>
  );
}

function ScaFindingReport({ finding }: { finding: Finding }) {
  const report = buildStoredFindingReport(finding);
  const metadata = finding.metadata as Record<string, unknown> | undefined;
  const fixVersion = typeof metadata?.fixVersion === "string" ? metadata.fixVersion : undefined;
  const reproCommand = buildReproductionCommand(finding);

  // Extract structured fields from summary
  const summaryLines = report.summary.split("\n\n");
  const whatIsWrong = summaryLines.find(line => line.includes("What is wrong:"))?.replace(/^What is wrong:\s*/i, "") || "";
  const whereInfo = summaryLines.find(line => line.includes("Where:"))?.replace(/^Where:\s*/i, "") || "";

  return (
    <section className="finding-detail-report surface-card min-w-0 max-w-full space-y-5 overflow-hidden p-4">
      {/* Issue Section */}
      <ReportBlock title="Issue" icon={<span className="text-lg">ℹ️</span>}>
        <div className="space-y-3">
          <p className="text-sm font-semibold text-foreground">
            {stripReportMarkdown(report.vulnerabilityName)}
          </p>
          {finding.ruleId && (
            <div className="rounded-lg border border-border/60 bg-muted/30 p-3 space-y-2">
              <div>
                <p className="text-xs font-medium text-muted-foreground">Vulnerable Dependency</p>
                <code className="text-sm font-mono text-foreground">{finding.ruleId}</code>
              </div>
              {fixVersion && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Fixed in Version</p>
                  <code className="text-sm font-mono text-foreground">{fixVersion}</code>
                </div>
              )}
              {whereInfo && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground">Location</p>
                  <code className="text-sm font-mono text-foreground">{whereInfo}</code>
                </div>
              )}
            </div>
          )}
          {whatIsWrong && (
            <div className="rounded-lg border border-border/60 bg-muted/30 p-3">
              <p className="text-xs font-medium text-muted-foreground mb-2">What is wrong</p>
              <p className="text-sm leading-relaxed text-foreground">
                <ReportRichText text={whatIsWrong} />
              </p>
            </div>
          )}
        </div>
      </ReportBlock>

      {/* Why It Matters Section */}
      <div className="border-t border-border/40 pt-4">
        <ReportBlock title="Why it Matters" icon={<span className="text-lg">⚠️</span>}>
          <div className="space-y-2">
            <p className="text-sm leading-relaxed text-foreground font-medium">
              {stripReportMarkdown(report.summary.split("\n\n")[0] || "A vulnerable dependency was identified.")}
            </p>
            <p className="text-sm leading-relaxed text-muted-foreground">
              This package is no longer receiving security updates and may contain exploitable vulnerabilities. Attackers can target known weaknesses in older versions.
            </p>
          </div>
        </ReportBlock>
      </div>

      {/* Customer Impact Section */}
      <div className="border-t border-border/40 pt-4">
        <ReportBlock title="Customer Impact" icon={<span className="text-lg">👥</span>}>
          <div className="rounded-lg border border-orange-200 bg-orange-50 p-3">
            <ReportRichText text={report.impact} />
          </div>
        </ReportBlock>
      </div>

      {/* Remediation Section */}
      <div className="border-t border-border/40 pt-4">
        <ReportBlock title="Remediation" icon={<span className="text-lg">🔧</span>}>
          <ol className="space-y-3 list-decimal pl-5">
            {report.remediation.map((step, i) => (
              <li key={i} className="text-sm text-muted-foreground leading-relaxed">
                <ReportRichText text={step} />
              </li>
            ))}
          </ol>
        </ReportBlock>
      </div>

      {/* How to Fix Section */}
      {reproCommand && (
        <div className="border-t border-border/40 pt-4">
          <ReportBlock title="How to Fix" icon={<span className="text-lg">💻</span>}>
            <div className="space-y-3">
              <pre className="max-w-full overflow-x-auto rounded-lg border border-border/60 bg-muted/80 p-3 text-xs font-mono leading-relaxed text-foreground">
                {reproCommand}
              </pre>
              <CopyCommandButton command={reproCommand} />
            </div>
          </ReportBlock>
        </div>
      )}
    </section>
  );
}

function IacFindingReport({
  finding,
  scanId,
}: {
  finding: Finding;
  scanId: string;
}) {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<AiSuggestFixResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchAiOutput() {
      try {
        const res = await fetch(
          `/api/scans/${scanId}/findings/${finding.id}/suggest-fix`,
          { method: "POST" },
        );
        const json = (await res.json()) as AiSuggestFixResponse & { error?: string };
        if (!res.ok) {
          throw new Error(json.error || "Failed to generate AI output");
        }
        setData(json);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to fetch AI output");
      } finally {
        setLoading(false);
      }
    }

    fetchAiOutput();
  }, [finding.id, scanId]);

  const report = buildStoredFindingReport(finding);
  const reproCommand = buildReproductionCommand(finding);

  return (
    <section className="finding-detail-report surface-card min-w-0 max-w-full space-y-5 overflow-hidden p-4">
      {loading ? (
        <ReportBlock title="AI Analysis" icon={<span className="text-lg">✨</span>}>
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-primary animate-pulse" />
            <p className="text-sm text-muted-foreground">Analyzing with AI...</p>
          </div>
        </ReportBlock>
      ) : error ? (
        <ReportBlock title="AI Analysis" icon={<span className="text-lg">⚠️</span>}>
          <p className="text-sm text-red-600">{error}</p>
        </ReportBlock>
      ) : data ? (
        <>
          {/* Issue Section */}
          <ReportBlock title="Issue" icon={<span className="text-lg">ℹ️</span>}>
            <div className="space-y-2">
              <ReportRichText text={data.summary} />
            </div>
          </ReportBlock>

          {/* Why It Matters Section */}
          <div className="border-t border-border/40 pt-4">
            <ReportBlock title="Why it Matters" icon={<span className="text-lg">⚠️</span>}>
              <div className="flex gap-2">
                <span className="text-lg">🔴</span>
                <ReportRichText text={report.impact} />
              </div>
            </ReportBlock>
          </div>

          {/* Locate Issue Section */}
          {reproCommand && (
            <div className="border-t border-border/40 pt-4">
              <ReportBlock title="Locate in Code" icon={<span className="text-lg">📍</span>}>
                <div className="space-y-3">
                  <pre className="max-w-full overflow-x-auto rounded-lg border border-border/60 bg-muted/80 p-3 text-xs font-mono leading-relaxed text-foreground">
                    {reproCommand}
                  </pre>
                  <CopyCommandButton command={reproCommand} />
                </div>
              </ReportBlock>
            </div>
          )}

          {/* What to Change Section */}
          <div className="border-t border-border/40 pt-4">
            <ReportBlock title="What to Change" icon={<span className="text-lg">🔧</span>}>
              <ReportRichText text={data.developerFix} />
            </ReportBlock>
          </div>

          {/* Verification Section */}
          {data.verificationSteps.length > 0 && (
            <div className="border-t border-border/40 pt-4">
              <ReportBlock title="How to Validate" icon={<span className="text-lg">✓</span>}>
                <ol className="space-y-2 list-decimal pl-5">
                  {data.verificationSteps.map((step, i) => (
                    <li key={i} className="text-sm text-muted-foreground">
                      <ReportRichText text={step} />
                    </li>
                  ))}
                </ol>
              </ReportBlock>
            </div>
          )}

          {/* Suggested Patch Section */}
          {data.optionalUnifiedDiff && (
            <div className="border-t border-border/40 pt-4">
              <ReportBlock title="Suggested Patch (Diff)" icon={<span className="text-lg">📝</span>}>
                <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border/60 bg-muted/80 p-3 text-xs font-mono">
                  {data.optionalUnifiedDiff}
                </pre>
              </ReportBlock>
            </div>
          )}
        </>
      ) : (
        <ReportBlock title="Impact" icon={<span className="text-lg">⚠️</span>}>
          <ReportRichText text={report.impact} />
        </ReportBlock>
      )}
    </section>
  );
}

function ContainerFindingReport({ finding }: { finding: Finding }) {
  const report = buildStoredFindingReport(finding);
  const metadata = finding.metadata as Record<string, unknown> | undefined;
  const reproCommand = buildReproductionCommand(finding);
  const image = typeof metadata?.image === "string" ? metadata.image : null;
  const packageName = typeof metadata?.packageName === "string" ? metadata.packageName : null;
  const packageVersion = typeof metadata?.packageVersion === "string" ? metadata.packageVersion : null;
  const fixVersion = typeof metadata?.fixVersion === "string" ? metadata.fixVersion : null;

  return (
    <section className="finding-detail-report surface-card min-w-0 max-w-full space-y-5 overflow-hidden p-4">
      {image && (
        <ReportBlock title="Container Image" icon={<span className="text-lg">🐳</span>}>
          <div className="rounded-lg border border-border/60 bg-muted/30 p-3">
            <p className="text-xs font-medium text-muted-foreground">Image</p>
            <code className="text-sm font-mono text-foreground">{image}</code>
          </div>
        </ReportBlock>
      )}

      {packageName && (
        <ReportBlock title="Affected Package" icon={<span className="text-lg">📦</span>}>
          <div className="rounded-lg border border-border/60 bg-muted/30 p-3 space-y-2">
            <div>
              <p className="text-xs font-medium text-muted-foreground">Package</p>
              <code className="text-sm font-mono text-foreground">
                {packageName}
                {packageVersion && `@${packageVersion}`}
              </code>
            </div>
            {fixVersion && (
              <div>
                <p className="text-xs font-medium text-muted-foreground">Fixed in Version</p>
                <code className="text-sm font-mono text-foreground">{fixVersion}</code>
              </div>
            )}
          </div>
        </ReportBlock>
      )}

      {reproCommand && (
        <ReportBlock title="How to Scan" icon={<span className="text-lg">🔍</span>}>
          <div className="space-y-3">
            <pre className="max-w-full overflow-x-auto rounded-lg border border-border/60 bg-muted/80 p-3 text-xs font-mono leading-relaxed text-foreground">
              {reproCommand}
            </pre>
            <CopyCommandButton command={reproCommand} />
          </div>
        </ReportBlock>
      )}

      <ReportBlock title="Impact" icon={<span className="text-lg">⚠️</span>}>
        <ReportRichText text={report.impact} />
      </ReportBlock>

      <ReportBlock title="Remediation" icon={<span className="text-lg">🔧</span>}>
        <ReportPlainList items={report.remediation} />
      </ReportBlock>
    </section>
  );
}

function CopyCommandButton({ command }: { command: string }) {
  const [busy, setBusy] = useState(false);

  async function copyCommand() {
    setBusy(true);
    try {
      await navigator.clipboard.writeText(command);
      toast.success("Command copied");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to copy command");
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
      onClick={() => void copyCommand()}
    >
      <Copy className="h-3.5 w-3.5 shrink-0" aria-hidden />
      {busy ? "Copying…" : "Copy command"}
    </Button>
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

  if (details.length === 0) return null;

  return (
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
  );
}

interface AiSuggestFixResponse {
  summary: string;
  developerFix: string;
  verificationSteps: string[];
  optionalUnifiedDiff: string | null;
}

function FindingReportSections({ finding, sourceContext }: { finding: Finding; sourceContext?: FindingScanSourceContext }) {
  if (isPatternBasedScanner(finding.scanner)) {
    return <PatternMatchReport finding={finding} />;
  }

  const isSecret = finding.scanner?.startsWith("SECRETS");
  if (isSecret) {
    return <SecretFindingReport finding={finding} />;
  }

  const isSca = finding.scanner === "SCA";
  if (isSca) {
    return <ScaFindingReport finding={finding} />;
  }

  const isIac = finding.scanner === "IAC";
  if (isIac && sourceContext?.scanId) {
    return <IacFindingReport finding={finding} scanId={sourceContext.scanId} />;
  }

  const isContainer = finding.scanner === "CONTAINER";
  if (isContainer) {
    return <ContainerFindingReport finding={finding} />;
  }

  const report = buildStoredFindingReport(finding);
  const reproCommand = buildReproductionCommand(finding);

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

          {report.stepsToReproduce.length > 0 && (
            <ReportBlock title="Steps to Reproduce" icon="🔧">
              <ReportPlainList items={report.stepsToReproduce} />
            </ReportBlock>
          )}

          {reproCommand && (
            <ReportBlock title="Example Command" icon="💻">
              <div className="space-y-3">
                <pre className="max-w-full overflow-x-auto rounded-lg border border-border/60 bg-muted/80 p-3 text-xs font-mono leading-relaxed text-foreground">
                  {reproCommand}
                </pre>
                <CopyCommandButton command={reproCommand} />
              </div>
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
