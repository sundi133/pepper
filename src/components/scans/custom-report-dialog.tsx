"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import useSWR from "swr";
import { AlertTriangle, CheckCircle2, FileText, Globe, Loader2, ShieldCheck, Sparkles, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { jsonFetcher } from "@/lib/fetcher";

interface TemplateOption {
  id: string;
  name: string;
  description: string | null;
}

interface ReportSummary {
  id: string;
  templateName: string;
  title: string | null;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  progress: number;
  stage: string | null;
  errorMessage: string | null;
  createdBy: string | null;
  createdAt: string;
}

interface ReportDetail extends ReportSummary {
  model: string | null;
  steps: Array<{ at: string; message: string }> | null;
  grounding: {
    cited: number;
    removed: string[];
    corrected: number;
    droppedLines: number;
    emptySections: number;
    warnings: string[];
  } | null;
}

const isActive = (s: string) => s === "QUEUED" || s === "RUNNING";

function DownloadButtons({ base }: { base: string }) {
  const open = (fmt: string) => window.open(`${base}/download?format=${fmt}`, "_blank");
  return (
    <div className="flex flex-wrap gap-1.5">
      <Button size="sm" variant="outline" className="h-7 gap-1.5 text-xs" onClick={() => open("html")}>
        <Globe className="h-3.5 w-3.5" /> View
      </Button>
      <Button size="sm" variant="outline" className="h-7 gap-1.5 text-xs" onClick={() => open("pdf")}>
        <FileText className="h-3.5 w-3.5" /> PDF
      </Button>
      <Button size="sm" variant="outline" className="h-7 gap-1.5 text-xs" onClick={() => open("md")}>
        <FileText className="h-3.5 w-3.5" /> Markdown
      </Button>
    </div>
  );
}

/** Live status of one report: progress while it runs, downloads when done. */
function ReportStatus({ scanId, reportId }: { scanId: string; reportId: string }) {
  const base = `/api/scans/${scanId}/custom-reports/${reportId}`;
  const { data } = useSWR<ReportDetail>(base, jsonFetcher, {
    refreshInterval: (d) => (!d || isActive(d.status) ? 2000 : 0),
  });
  if (!data) {
    return (
      <div className="flex items-center gap-2 rounded-lg border p-3 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading report status…
      </div>
    );
  }
  const g = data.grounding;
  return (
    <div className="space-y-3 rounded-lg border p-3">
      <div className="flex items-center justify-between gap-2 text-sm">
        <span className="font-medium">{data.title || data.templateName}</span>
        <span className="text-xs text-muted-foreground">{data.model}</span>
      </div>
      {isActive(data.status) && (
        <>
          <Progress value={data.progress} />
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            {data.stage || "Queued"} · {data.progress}%
          </p>
        </>
      )}
      {data.status === "FAILED" && (
        <p className="flex items-start gap-2 text-sm text-red-600 dark:text-red-400">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          {data.errorMessage || "Report generation failed."}
        </p>
      )}
      {data.status === "COMPLETED" && (
        <>
          <p className="flex items-start gap-2 text-sm text-emerald-700 dark:text-emerald-400">
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> Report ready.
          </p>
          {g && (
            <p className="flex items-start gap-2 text-xs text-muted-foreground">
              <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {g.cited} finding reference{g.cited === 1 ? "" : "s"} verified against the scan
              {g.removed.length > 0 && ` · ${g.removed.length} citation${g.removed.length === 1 ? "" : "s"} of non-existent findings removed`}
              {g.emptySections > 0 && ` · ${g.emptySections} section${g.emptySections === 1 ? "" : "s"} could not be written`}
              {g.warnings.length > 0 && ` · ${g.warnings.length} count${g.warnings.length === 1 ? "" : "s"} to double-check`}
            </p>
          )}
          <DownloadButtons base={base} />
        </>
      )}
      {data.steps && data.steps.length > 0 && (
        <ul className="max-h-28 space-y-0.5 overflow-y-auto border-t pt-2 text-xs text-muted-foreground">
          {data.steps.slice(-8).map((s, i) => (
            <li key={i}>
              <span className="tabular-nums">{new Date(s.at).toLocaleTimeString()}</span> · {s.message}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * Scan page → Reports → "Custom report…": pick an organization template,
 * add optional instructions, generate in the background, then view or
 * download. Earlier reports for the scan are listed underneath.
 */
export function CustomReportDialog({
  open,
  onOpenChange,
  scanId,
  canGenerate,
  canDeleteAny,
  userId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  scanId: string;
  canGenerate: boolean;
  canDeleteAny: boolean;
  userId?: string;
}) {
  const [templates, setTemplates] = useState<TemplateOption[] | null>(null);
  const [templateId, setTemplateId] = useState("");
  const [instructions, setInstructions] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const listUrl = `/api/scans/${scanId}/custom-reports`;
  const { data, mutate } = useSWR<{ reports: ReportSummary[] }>(open ? listUrl : null, jsonFetcher, {
    refreshInterval: (d) => (d?.reports?.some((r) => isActive(r.status)) ? 3000 : 0),
  });
  const reports = useMemo(() => data?.reports ?? [], [data]);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    fetch("/api/settings/report-templates")
      .then((r) => (r.ok ? r.json() : { templates: [] }))
      .then((j: { templates: TemplateOption[] }) => {
        if (cancelled) return;
        setTemplates(j.templates);
        setTemplateId((cur) => cur || j.templates[0]?.id || "");
      })
      .catch(() => !cancelled && setTemplates([]));
    return () => {
      cancelled = true;
    };
  }, [open]);

  // Show the newest active report (e.g. one started from another tab).
  useEffect(() => {
    if (!selected && reports.length > 0 && isActive(reports[0].status)) setSelected(reports[0].id);
  }, [reports, selected]);

  async function generate() {
    setSubmitting(true);
    try {
      const res = await fetch(listUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ templateId, instructions: instructions.trim() || null }),
      });
      const j = (await res.json().catch(() => ({}))) as { reportId?: string; error?: string };
      if (res.status === 409 && j.reportId) {
        setSelected(j.reportId);
        toast.info(j.error || "A report is already being generated.");
        return;
      }
      if (!res.ok || !j.reportId) throw new Error(j.error || "Could not start the report");
      setSelected(j.reportId);
      mutate();
      toast.success("Report generation started");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not start the report");
    } finally {
      setSubmitting(false);
    }
  }

  async function remove(r: ReportSummary) {
    if (!confirm(`Delete the report "${r.title || r.templateName}"?`)) return;
    const res = await fetch(`${listUrl}/${r.id}`, { method: "DELETE" });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) {
      toast.error(j.error || "Failed to delete the report");
      return;
    }
    if (selected === r.id) setSelected(null);
    mutate();
  }

  const busy = reports.some((r) => isActive(r.status));

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-violet-600" /> Custom report
          </DialogTitle>
          <DialogDescription>
            AI fills one of your organization&apos;s report templates with this scan&apos;s data. It cites only findings
            that exist in the scan. Generation runs in the background and can take a few minutes.
          </DialogDescription>
        </DialogHeader>

        {templates === null ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading templates…
          </div>
        ) : templates.length === 0 ? (
          <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
            No report templates yet.{" "}
            <Link href="/settings/report-templates" className="text-primary hover:underline">
              Create one under Settings → Report Templates
            </Link>
            .
          </p>
        ) : (
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Template</Label>
              <Select value={templateId} onValueChange={setTemplateId}>
                <SelectTrigger>
                  <SelectValue placeholder="Choose a template" />
                </SelectTrigger>
                <SelectContent>
                  {templates.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {templates.find((t) => t.id === templateId)?.description && (
                <p className="text-xs text-muted-foreground">{templates.find((t) => t.id === templateId)?.description}</p>
              )}
            </div>
            <div className="space-y-2">
              <Label>Extra instructions (optional)</Label>
              <Textarea
                value={instructions}
                onChange={(e) => setInstructions(e.target.value)}
                maxLength={2000}
                rows={3}
                placeholder="e.g., Focus on the payment service; this goes to the board."
              />
            </div>
            {!canGenerate && (
              <p className="text-xs text-muted-foreground">Viewers can open existing reports but not generate new ones.</p>
            )}
          </div>
        )}

        {selected && <ReportStatus scanId={scanId} reportId={selected} />}

        {reports.length > 0 && (
          <div className="space-y-1.5">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Reports for this scan</p>
            <ul className="divide-y rounded-lg border text-sm">
              {reports.map((r) => (
                <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                  <button
                    type="button"
                    className="min-w-0 flex-1 truncate text-left hover:underline"
                    onClick={() => setSelected(r.id)}
                    title="Show status"
                  >
                    {r.title || r.templateName}
                    <span className="ml-2 text-xs text-muted-foreground">{new Date(r.createdAt).toLocaleString()}</span>
                  </button>
                  <span className="flex items-center gap-2">
                    {isActive(r.status) ? (
                      <span className="flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400">
                        <Loader2 className="h-3 w-3 animate-spin" /> {r.progress}%
                      </span>
                    ) : r.status === "FAILED" ? (
                      <span className="text-xs text-red-600 dark:text-red-400">failed</span>
                    ) : (
                      <DownloadButtons base={`${listUrl}/${r.id}`} />
                    )}
                    {!isActive(r.status) && canGenerate && (canDeleteAny || r.createdBy === userId) && (
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-muted-foreground hover:text-destructive"
                        title="Delete report"
                        onClick={() => remove(r)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
          {templates && templates.length > 0 && (
            <Button onClick={generate} disabled={!canGenerate || !templateId || submitting || busy}>
              {submitting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Sparkles className="mr-2 h-4 w-4" />}
              {busy ? "Generating…" : "Generate report"}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
