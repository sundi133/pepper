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
import { ExternalLink, Sparkles, GitPullRequest, Copy } from "lucide-react";
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
    <section className="space-y-4 rounded-xl border border-border/60 bg-muted/20 p-4 shadow-sm">
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
              className="overflow-x-auto rounded-lg border border-border/60 bg-muted/80 p-3 text-xs font-mono leading-relaxed text-foreground"
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

  const report = buildStoredFindingReport(finding);

  return (
    <section className="space-y-4 rounded-xl border bg-card p-4 shadow-sm">
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
    <>
      <CopyReportButton finding={finding} />
      <CopyAiPromptButton finding={finding} sourceContext={sourceContext} tool="claude" />
      <CopyAiPromptButton finding={finding} sourceContext={sourceContext} tool="cursor" />
      {sourceContext?.scanId ? (
        <>
          <SuggestAiFixButton finding={finding} scanId={sourceContext.scanId} />
          <OpenFixPrButton finding={finding} sourceContext={sourceContext} />
        </>
      ) : null}
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
  const scanId = sourceContext?.scanId?.trim();
  if (!scanId) return null;

  const blockReason = fixPrUnavailableReason(sourceContext, finding.filePath);
  const hasGithubRepo = Boolean(resolveGithubRepoForFixPr(sourceContext));
  const canOpen = !blockReason;

  async function openPr() {
    let manualRepoUrl: string | undefined;
    if (!hasGithubRepo) {
      const input = window.prompt(
        "Enter the GitHub repository for this fix PR (owner/repo or https://github.com/owner/repo):",
      );
      if (!input?.trim()) return;
      manualRepoUrl = input.trim();
    }

    setBusy(true);
    try {
      const outcome = await runOpenFixPrFlow(scanId!, finding.id, {
        repoUrl: manualRepoUrl,
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

  const label = busy ? "Opening…" : "Open fix PR";
  const button = (
    <Button
      type="button"
      variant="default"
      size="sm"
      className="h-8 gap-1.5 text-xs font-semibold"
      disabled={busy || !canOpen}
      onClick={() => void openPr()}
    >
      <GitPullRequest className="h-3.5 w-3.5 shrink-0" aria-hidden />
      {label}
    </Button>
  );

  if (canOpen) {
    return button;
  }

  const hint = `${blockReason} Connect GitHub via OAuth when prompted. You can also enter owner/repo when opening the PR.`;

  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex cursor-default">
            {button}
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

        <ScrollArea className="h-[calc(100vh-10rem)]">
          <div className="space-y-5 px-6 py-5">
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
            <FindingLocationRow finding={finding} sourceContext={sourceContext} />
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2">
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

      <div className="w-full max-w-full space-y-5 overflow-hidden p-5">
        <FindingReportSections finding={finding} />
      </div>
    </div>
  );
}
