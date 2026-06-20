"use client";

import { Fragment, useState, type ReactNode } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "./scan-status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { SCANNER_LABELS } from "@/lib/constants";
import { riskScoreLabel } from "@/lib/risk-score";
import {
  type FixPrScanSourceContext,
  fixPrUnavailableReason,
  resolveGithubRepoForFixPr,
} from "@/lib/open-fix-pr-client";
import { runOpenFixPrFlow } from "@/lib/open-fix-pr-flow";
import { FileCode, ChevronDown, ChevronRight, GitPullRequest, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

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
  riskScore?: number | null;
  isNew?: boolean | null;
  metadata?: Record<string, unknown>;
}

const STATUS_LABELS: Record<string, { label: string; color: string }> = {
  OPEN: {
    label: "Open",
    color:
      "bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-400",
  },
  IN_PROGRESS: {
    label: "In Progress",
    color: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-400",
  },
  FALSE_POSITIVE: {
    label: "False Positive",
    color: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400",
  },
  ACCEPTED_RISK: {
    label: "Accepted",
    color:
      "bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-400",
  },
  RESOLVED: {
    label: "Resolved",
    color: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-400",
  },
};

interface FindingsTableProps {
  findings: Finding[];
  onSelect?: (finding: Finding) => void;
  selectedId?: string;
  onBulkStatusChange?: () => void;
  renderExpanded?: (finding: Finding) => ReactNode;
  /** When set, each row shows an action to open a GitHub fix PR for findings with a file path. */
  fixPrSource?: FixPrScanSourceContext;
}

export function FindingsTable({
  findings,
  onSelect,
  selectedId,
  onBulkStatusChange,
  renderExpanded,
  fixPrSource,
}: FindingsTableProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState<string>("");
  const [bulkLoading, setBulkLoading] = useState(false);

  // Bulk Fix PR state
  const [fixPrDialogOpen, setFixPrDialogOpen] = useState(false);
  const [fixPrRunning, setFixPrRunning] = useState(false);
  const [fixPrResults, setFixPrResults] = useState<
    Array<{ findingId: string; title: string; ok: boolean; prUrl?: string; error?: string }>
  >([]);
  const [fixPrCurrent, setFixPrCurrent] = useState<number>(0);
  const [fixPrTotal, setFixPrTotal] = useState<number>(0);

  // Batch FP verification state
  const [verifyLoading, setVerifyLoading] = useState(false);
  const [verifyDialogOpen, setVerifyDialogOpen] = useState(false);
  const [verifyResults, setVerifyResults] = useState<{
    total: number;
    falsePositives: number;
    truePositives: number;
    appliedCount: number;
    results: Array<{
      findingId: string;
      isFalsePositive: boolean;
      confidence: number;
      reasoning: string;
      recommendation: string;
    }>;
  } | null>(null);

  const allSelected = findings.length > 0 && selected.size === findings.length;
  const someSelected = selected.size > 0 && selected.size < findings.length;

  function toggleAll() {
    if (allSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(findings.map((f) => f.id)));
    }
  }

  function toggleOne(id: string) {
    const next = new Set(selected);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setSelected(next);
  }

  async function handleBulkUpdate() {
    if (!bulkStatus || selected.size === 0) return;
    setBulkLoading(true);

    try {
      const res = await fetch("/api/findings/bulk", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findingIds: Array.from(selected),
          status: bulkStatus,
        }),
      });

      if (!res.ok) throw new Error("Failed to update");
      const result = await res.json();
      toast.success(
        `Updated ${result.updated} findings to ${bulkStatus.replace("_", " ").toLowerCase()}`,
      );
      setSelected(new Set());
      setBulkStatus("");
      onBulkStatusChange?.();
    } catch {
      toast.error("Failed to update findings");
    } finally {
      setBulkLoading(false);
    }
  }

  async function handleBatchVerify() {
    if (selected.size === 0) return;
    setVerifyLoading(true);
    setVerifyDialogOpen(true);
    setVerifyResults(null);
    try {
      const res = await fetch("/api/findings/verify-batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findingIds: Array.from(selected).slice(0, 50),
          autoApply: false,
        }),
      });
      if (!res.ok) {
        const j = await res.json();
        throw new Error(j.error || "Verification failed");
      }
      setVerifyResults(await res.json());
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Batch verification failed");
      setVerifyDialogOpen(false);
    } finally {
      setVerifyLoading(false);
    }
  }

  async function handleApplyVerifiedFps() {
    if (!verifyResults) return;
    const fpIds = verifyResults.results
      .filter((r) => r.isFalsePositive && r.confidence >= 0.85)
      .map((r) => r.findingId);
    if (fpIds.length === 0) return;

    try {
      const res = await fetch("/api/findings/bulk", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findingIds: fpIds,
          status: "FALSE_POSITIVE",
          statusNote: "AI batch verification — marked as false positive",
        }),
      });
      if (!res.ok) throw new Error("Failed to apply");
      const result = await res.json();
      toast.success(`Marked ${result.updated} findings as false positive`);
      setVerifyDialogOpen(false);
      setSelected(new Set());
      onBulkStatusChange?.();
    } catch {
      toast.error("Failed to apply false positive status");
    }
  }

  async function handleBulkFixPr() {
    if (selected.size === 0 || !fixPrSource) return;
    const selectedFindings = findings.filter((f) => selected.has(f.id) && f.filePath);
    if (selectedFindings.length === 0) {
      toast.error("No selected findings have file paths");
      return;
    }

    setFixPrDialogOpen(true);
    setFixPrRunning(true);
    setFixPrResults([]);
    setFixPrCurrent(0);
    setFixPrTotal(selectedFindings.length);

    const results: typeof fixPrResults = [];

    for (let i = 0; i < selectedFindings.length; i++) {
      const f = selectedFindings[i];
      setFixPrCurrent(i + 1);

      try {
        const outcome = await runOpenFixPrFlow(
          fixPrSource.scanId,
          f.id,
          { skipConfirm: true },
        );
        if ("redirected" in outcome) {
          results.push({ findingId: f.id, title: f.title, ok: false, error: "GitHub OAuth required — redirecting" });
          break;
        }
        if (outcome.ok) {
          results.push({ findingId: f.id, title: f.title, ok: true, prUrl: outcome.pullRequestUrl });
        } else {
          results.push({ findingId: f.id, title: f.title, ok: false, error: outcome.error });
        }
      } catch (e) {
        results.push({
          findingId: f.id,
          title: f.title,
          ok: false,
          error: e instanceof Error ? e.message : "Unknown error",
        });
      }

      setFixPrResults([...results]);
    }

    setFixPrRunning(false);
    const successCount = results.filter((r) => r.ok).length;
    if (successCount > 0) {
      toast.success(`Opened ${successCount} fix PR${successCount > 1 ? "s" : ""}`);
    }
  }

  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
        <FileCode className="h-12 w-12 mb-4" />
        <p className="text-lg font-medium">No findings</p>
        <p className="text-sm">This scan did not detect any issues.</p>
      </div>
    );
  }

  return (
    <div className="min-w-0 w-full max-w-full overflow-hidden">
      {/* Bulk Action Bar */}
      {selected.size > 0 && (
        <div className="flex items-center gap-3 mb-3 rounded-lg border bg-muted/50 px-4 py-2">
          <span className="text-sm font-medium">{selected.size} selected</span>
          <Select value={bulkStatus} onValueChange={setBulkStatus}>
            <SelectTrigger className="h-8 w-[160px] text-xs">
              <SelectValue placeholder="Set status..." />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="OPEN">Open</SelectItem>
              <SelectItem value="IN_PROGRESS">In Progress</SelectItem>
              <SelectItem value="FALSE_POSITIVE">False Positive</SelectItem>
              <SelectItem value="ACCEPTED_RISK">Accepted Risk</SelectItem>
              <SelectItem value="RESOLVED">Resolved</SelectItem>
            </SelectContent>
          </Select>
          <Button
            size="sm"
            className="h-8 text-xs"
            onClick={handleBulkUpdate}
            disabled={!bulkStatus || bulkLoading}
          >
            {bulkLoading ? "Updating..." : "Apply"}
          </Button>
          <div className="mx-1 h-5 w-px bg-border" />
          <Button
            size="sm"
            variant="secondary"
            className="h-8 gap-1.5 text-xs"
            onClick={handleBatchVerify}
            disabled={verifyLoading}
          >
            <ShieldCheck className="h-3.5 w-3.5 shrink-0" aria-hidden />
            {verifyLoading ? "Verifying..." : "Verify FP"}
          </Button>
          {fixPrSource && (
            <Button
              size="sm"
              variant="secondary"
              className="h-8 gap-1.5 text-xs"
              onClick={() => {
                if (window.confirm(
                  `Open fix PRs for ${selected.size} selected finding(s)? Each finding creates a separate branch and PR. This uses your LLM to generate fixes.`
                )) {
                  void handleBulkFixPr();
                }
              }}
              disabled={fixPrRunning}
            >
              <GitPullRequest className="h-3.5 w-3.5 shrink-0" aria-hidden />
              {fixPrRunning ? "Fixing..." : "Fix PRs"}
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            className="h-8 text-xs"
            onClick={() => setSelected(new Set())}
          >
            Clear
          </Button>
        </div>
      )}

      {/* Batch FP Verification Results Dialog */}
      <Dialog open={verifyDialogOpen} onOpenChange={setVerifyDialogOpen}>
        <DialogContent className="max-h-[85vh] max-w-lg gap-0 overflow-hidden p-0 sm:max-w-lg">
          <DialogHeader className="border-b border-border/60 px-6 py-4">
            <DialogTitle className="text-left text-base">
              Batch FP Verification Results
            </DialogTitle>
          </DialogHeader>
          <div className="max-h-[calc(85vh-8rem)] overflow-y-auto px-6 py-4 space-y-4">
            {verifyLoading ? (
              <p className="text-sm text-muted-foreground">
                Analyzing {selected.size} findings with AI...
              </p>
            ) : verifyResults ? (
              <>
                <div className="grid grid-cols-3 gap-3 text-center">
                  <div className="rounded-lg border bg-muted/30 p-3">
                    <p className="text-2xl font-bold">{verifyResults.total}</p>
                    <p className="text-xs text-muted-foreground">Analyzed</p>
                  </div>
                  <div className="rounded-lg border bg-green-50 dark:bg-green-900/20 p-3">
                    <p className="text-2xl font-bold text-green-700 dark:text-green-400">
                      {verifyResults.falsePositives}
                    </p>
                    <p className="text-xs text-muted-foreground">Likely FP</p>
                  </div>
                  <div className="rounded-lg border bg-red-50 dark:bg-red-900/20 p-3">
                    <p className="text-2xl font-bold text-red-700 dark:text-red-400">
                      {verifyResults.truePositives}
                    </p>
                    <p className="text-xs text-muted-foreground">Likely TP</p>
                  </div>
                </div>

                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {verifyResults.results.map((r) => {
                    const f = findings.find((ff) => ff.id === r.findingId);
                    return (
                      <div
                        key={r.findingId}
                        className="flex items-start gap-2 rounded border p-2 text-xs"
                      >
                        <Badge
                          className={
                            r.isFalsePositive
                              ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 shrink-0"
                              : "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 shrink-0"
                          }
                        >
                          {r.isFalsePositive ? "FP" : "TP"}
                        </Badge>
                        <div className="min-w-0 flex-1">
                          <p className="font-medium truncate">
                            {f?.title ?? r.findingId}
                          </p>
                          <p className="text-muted-foreground line-clamp-2">
                            {r.reasoning}
                          </p>
                        </div>
                        <span className="text-muted-foreground shrink-0">
                          {Math.round(r.confidence * 100)}%
                        </span>
                      </div>
                    );
                  })}
                </div>

                {verifyResults.falsePositives > 0 && (
                  <Button
                    size="sm"
                    className="w-full"
                    onClick={handleApplyVerifiedFps}
                  >
                    Mark {
                      verifyResults.results.filter(
                        (r) => r.isFalsePositive && r.confidence >= 0.85,
                      ).length
                    } high-confidence findings as False Positive
                  </Button>
                )}
              </>
            ) : null}
          </div>
        </DialogContent>
      </Dialog>

      {/* Bulk Fix PR Results Dialog */}
      <Dialog open={fixPrDialogOpen} onOpenChange={(open) => { if (!fixPrRunning) setFixPrDialogOpen(open); }}>
        <DialogContent className="max-h-[85vh] max-w-lg gap-0 overflow-hidden p-0 sm:max-w-lg">
          <DialogHeader className="border-b border-border/60 px-6 py-4">
            <DialogTitle className="text-left text-base">
              {fixPrRunning
                ? `Opening Fix PRs (${fixPrCurrent}/${fixPrTotal})...`
                : "Fix PR Results"}
            </DialogTitle>
          </DialogHeader>
          <div className="max-h-[calc(85vh-8rem)] overflow-y-auto px-6 py-4 space-y-3">
            {fixPrRunning && fixPrResults.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                Generating fix for finding {fixPrCurrent} of {fixPrTotal}...
              </p>
            ) : null}
            {fixPrResults.map((r) => (
              <div
                key={r.findingId}
                className="flex items-start gap-2 rounded border p-2 text-xs"
              >
                <Badge
                  className={
                    r.ok
                      ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 shrink-0"
                      : "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 shrink-0"
                  }
                >
                  {r.ok ? "PR" : "Fail"}
                </Badge>
                <div className="min-w-0 flex-1">
                  <p className="font-medium truncate">{r.title}</p>
                  {r.ok && r.prUrl ? (
                    <a
                      href={r.prUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-600 hover:underline dark:text-blue-400"
                    >
                      View PR
                    </a>
                  ) : r.error ? (
                    <p className="text-muted-foreground line-clamp-2">{r.error}</p>
                  ) : null}
                </div>
              </div>
            ))}
            {fixPrRunning && fixPrResults.length > 0 ? (
              <p className="text-xs text-muted-foreground">
                Processing finding {fixPrCurrent} of {fixPrTotal}...
              </p>
            ) : null}
          </div>
        </DialogContent>
      </Dialog>

      <Table className="table-fixed w-full">
        <TableHeader>
          <TableRow>
            <TableHead className="w-10">
              <Checkbox
                checked={allSelected}
                ref={(el) => {
                  if (el) {
                    (el as unknown as HTMLInputElement).indeterminate =
                      someSelected;
                  }
                }}
                onCheckedChange={toggleAll}
              />
            </TableHead>
            <TableHead className="w-16 text-center">Risk</TableHead>
            <TableHead className="w-24">Severity</TableHead>
            <TableHead className="w-[28%] min-w-0">Bug / Vulnerability</TableHead>
            <TableHead className="w-24">Status</TableHead>
            <TableHead className="w-32">Scanner</TableHead>
            <TableHead className="w-[18%] min-w-0">File</TableHead>
            {fixPrSource ? (
              <TableHead className="w-11 text-center" title="Open GitHub fix PR">
                <span className="sr-only">Open fix PR</span>
                <GitPullRequest
                  className="mx-auto h-4 w-4 text-muted-foreground"
                  aria-hidden
                />
              </TableHead>
            ) : null}
            <TableHead className="w-8" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.map((finding) => (
            <Fragment key={finding.id}>
              <TableRow
                className={`cursor-pointer ${selectedId === finding.id ? "bg-muted" : ""}`}
              >
                <TableCell onClick={(e) => e.stopPropagation()}>
                  <Checkbox
                    checked={selected.has(finding.id)}
                    onCheckedChange={() => toggleOne(finding.id)}
                  />
                </TableCell>
                <TableCell className="text-center" onClick={() => onSelect?.(finding)}>
                  <RiskScoreBadge score={finding.riskScore} />
                </TableCell>
                <TableCell onClick={() => onSelect?.(finding)}>
                  <SeverityBadge severity={finding.severity} />
                </TableCell>
                <TableCell
                  className="min-w-0 whitespace-normal"
                  onClick={() => onSelect?.(finding)}
                >
                  <div className="min-w-0">
                    <p className="break-words text-sm font-medium leading-snug">
                      {finding.title}
                    </p>
                    {finding.cweId && (
                      <span className="text-xs text-muted-foreground">
                        {finding.cweId}
                      </span>
                    )}
                  </div>
                </TableCell>
                <TableCell onClick={() => onSelect?.(finding)}>
                  {finding.status && STATUS_LABELS[finding.status] && (
                    <span
                      className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-medium ${STATUS_LABELS[finding.status].color}`}
                    >
                      {STATUS_LABELS[finding.status].label}
                    </span>
                  )}
                </TableCell>
                <TableCell onClick={() => onSelect?.(finding)}>
                  <Badge variant="outline" className="text-xs">
                    {SCANNER_LABELS[
                      finding.scanner as keyof typeof SCANNER_LABELS
                    ] || finding.scanner}
                  </Badge>
                </TableCell>
                <TableCell
                  className="min-w-0 whitespace-normal"
                  onClick={() => onSelect?.(finding)}
                >
                  {finding.filePath && (
                    <span className="block break-all font-mono text-xs text-muted-foreground">
                      {finding.filePath}
                      {finding.startLine ? `:${finding.startLine}` : ""}
                    </span>
                  )}
                </TableCell>
                {fixPrSource ? (
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <FindingFixPrIcon
                      finding={finding}
                      fixPrSource={fixPrSource}
                    />
                  </TableCell>
                ) : null}
                <TableCell onClick={() => onSelect?.(finding)}>
                  {selectedId === finding.id ? (
                    <ChevronDown className="h-4 w-4 text-muted-foreground" aria-hidden />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-muted-foreground" aria-hidden />
                  )}
                </TableCell>
              </TableRow>
              {selectedId === finding.id && renderExpanded && (
                <TableRow>
                  <TableCell
                    colSpan={fixPrSource ? 8 : 7}
                    className="!whitespace-normal bg-muted/30 p-0 align-top text-foreground"
                  >
                    <div className="min-w-0 w-full max-w-full overflow-hidden px-4 py-4">
                      {renderExpanded(finding)}
                    </div>
                  </TableCell>
                </TableRow>
              )}
            </Fragment>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function FindingFixPrIcon({
  finding,
  fixPrSource,
}: {
  finding: Finding;
  fixPrSource: FixPrScanSourceContext;
}) {
  const [busy, setBusy] = useState(false);
  const scanId = fixPrSource.scanId.trim();
  const blockReason = fixPrUnavailableReason(fixPrSource, finding.filePath);
  const hasGithubRepo = Boolean(
    fixPrSource && resolveGithubRepoForFixPr(fixPrSource),
  );
  const canOpen = !blockReason;

  async function openPr() {
    let manualRepoUrl: string | undefined;
    if (!hasGithubRepo) {
      const input = window.prompt(
        "Enter GitHub repository (owner/repo or URL) for this fix PR:",
      );
      if (!input?.trim()) return;
      manualRepoUrl = input.trim();
    }

    setBusy(true);
    try {
      const outcome = await runOpenFixPrFlow(scanId, finding.id, {
        repoUrl: manualRepoUrl,
      });
      if ("redirected" in outcome) return;
      if (!outcome.ok) {
        if (outcome.code !== "CANCELLED") toast.error(outcome.error);
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

  const iconButton = (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      className="h-8 w-8 shrink-0"
      disabled={busy || !canOpen}
      aria-label={busy ? "Opening pull request" : "Open fix pull request on GitHub"}
      onClick={() => void openPr()}
    >
      <GitPullRequest className="h-4 w-4" aria-hidden />
    </Button>
  );

  if (canOpen) {
    return iconButton;
  }

  const hint = `${blockReason} Connect GitHub via OAuth when prompted; set LLM under Settings → LLM.`;

  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span className="inline-flex">{iconButton}</span>
        </TooltipTrigger>
        <TooltipContent side="left" className="max-w-xs text-balance">
          {hint}
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

// ─── Risk Score Badge ────────────────────────────────────────────────────────

const RISK_COLORS: Record<ReturnType<typeof riskScoreLabel>, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300",
  high:     "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300",
  medium:   "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300",
  low:      "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400",
  info:     "bg-slate-100 text-slate-400 dark:bg-slate-900 dark:text-slate-500",
};

function RiskScoreBadge({ score }: { score?: number | null }) {
  if (score == null) return <span className="text-xs text-muted-foreground">—</span>;
  const label = riskScoreLabel(score);
  return (
    <TooltipProvider delayDuration={200}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className={`inline-flex items-center justify-center rounded-full px-1.5 py-0.5 text-[11px] font-bold tabular-nums ${RISK_COLORS[label]}`}
          >
            {score}
          </span>
        </TooltipTrigger>
        <TooltipContent side="top">
          Risk score {score}/100 — {label} priority
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
