"use client";

import { Fragment, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { toast } from "sonner";
import {
  ArrowUpRight,
  Check,
  ChevronDown,
  ChevronRight,
  GitBranch,
  GitPullRequest,
  Loader2,
  Minus,
  Sparkles,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  STEP_ORDER,
  applyRunEvent,
  initialRunView,
  type AttemptView,
  type ItemView,
  type RunView,
} from "@/lib/remediation/run-reducer";
import {
  TERMINAL_RUN_STATUSES,
  type RemediationItemStatus,
  type RemediationRunSnapshot,
  type RemediationStep,
  type RemediationStreamEvent,
  type StepStatus,
} from "@/lib/remediation/types";

const STEP_LABELS: Record<RemediationStep, string> = {
  locate: "Locate",
  context: "Gather context",
  analyze: "Analyze",
  fix: "Write fix",
  validate: "Validate",
  commit: "Commit",
};

const RUN_STATUS: Record<string, { label: string; dot: string; text: string }> = {
  QUEUED: { label: "Queued", dot: "bg-muted-foreground/50", text: "text-muted-foreground" },
  RUNNING: { label: "Running", dot: "bg-blue-500 animate-pulse", text: "text-blue-600 dark:text-blue-400" },
  COMPLETED: { label: "Completed", dot: "bg-emerald-500", text: "text-emerald-600 dark:text-emerald-400" },
  PARTIAL: { label: "Partially fixed", dot: "bg-amber-500", text: "text-amber-600 dark:text-amber-400" },
  FAILED: { label: "Failed", dot: "bg-red-500", text: "text-red-600 dark:text-red-400" },
  CANCELLED: { label: "Cancelled", dot: "bg-muted-foreground/50", text: "text-muted-foreground" },
};

const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: "bg-red-500",
  HIGH: "bg-orange-500",
  MEDIUM: "bg-amber-400",
  LOW: "bg-sky-400",
  INFO: "bg-slate-400",
};

const ITEM_STATUS_LABEL: Record<RemediationItemStatus, string> = {
  PENDING: "Queued",
  ANALYZING: "Analyzing",
  FIXING: "Writing fix",
  VALIDATING: "Validating",
  FIXED: "Fixed",
  FAILED: "Not fixed",
  SKIPPED: "Skipped",
};

const PROVIDER_NAMES: Record<string, string> = {
  github: "GitHub",
  azure_devops: "Azure DevOps",
  bitbucket: "Bitbucket",
};

const SECTION_LABEL = "text-[11px] font-medium uppercase tracking-wider text-muted-foreground";

function Severity({ severity }: { severity: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
      <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_DOT[severity] ?? SEVERITY_DOT.INFO}`} aria-hidden />
      {severity.charAt(0) + severity.slice(1).toLowerCase()}
    </span>
  );
}

/** Small round status glyph used for issues, steps and checks. */
function StatusGlyph({
  state,
  size = "md",
}: {
  state: "done" | "failed" | "skipped" | "running" | "idle";
  size?: "sm" | "md";
}) {
  const box = size === "sm" ? "h-4 w-4" : "h-5 w-5";
  const icon = size === "sm" ? "h-2.5 w-2.5" : "h-3 w-3";
  if (state === "running") {
    return (
      <span className={`${box} inline-flex shrink-0 items-center justify-center`}>
        <Loader2 className={`${size === "sm" ? "h-3.5 w-3.5" : "h-4 w-4"} animate-spin text-blue-500`} aria-label="In progress" />
      </span>
    );
  }
  const styles = {
    done: "bg-emerald-500 text-white",
    failed: "bg-red-500 text-white",
    skipped: "bg-muted text-muted-foreground",
    idle: "border border-border bg-background",
  }[state];
  return (
    <span className={`${box} ${styles} inline-flex shrink-0 items-center justify-center rounded-full`} aria-label={state}>
      {state === "done" && <Check className={icon} strokeWidth={3} aria-hidden />}
      {state === "failed" && <X className={icon} strokeWidth={3} aria-hidden />}
      {state === "skipped" && <Minus className={icon} strokeWidth={3} aria-hidden />}
    </span>
  );
}

function itemGlyphState(status: RemediationItemStatus) {
  if (status === "FIXED") return "done" as const;
  if (status === "FAILED") return "failed" as const;
  if (status === "SKIPPED") return "skipped" as const;
  if (status === "PENDING") return "idle" as const;
  return "running" as const;
}

function stepGlyphState(status?: StepStatus) {
  if (!status) return "idle" as const;
  return status === "done" ? ("done" as const) : status;
}

// ─── Tiny markdown renderer (headings, bullets, bold, inline code) ─────

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  return text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).map((p, i) => {
    const key = `${keyPrefix}-${i}`;
    if (p.startsWith("`") && p.endsWith("`") && p.length > 2) {
      return (
        <code key={key} className="rounded bg-muted px-1 py-0.5 font-mono text-[0.85em]">
          {p.slice(1, -1)}
        </code>
      );
    }
    if (p.startsWith("**") && p.endsWith("**") && p.length > 4) {
      return <strong key={key} className="font-medium text-foreground">{p.slice(2, -2)}</strong>;
    }
    return <Fragment key={key}>{p}</Fragment>;
  });
}

function MarkdownLite({ text }: { text: string }) {
  const blocks: ReactNode[] = [];
  let bullets: string[] = [];
  let para: string[] = [];
  const flush = (key: string) => {
    if (para.length) {
      blocks.push(
        <p key={`p-${key}`} className="leading-relaxed">
          {renderInline(para.join(" "), `p-${key}`)}
        </p>,
      );
      para = [];
    }
    if (bullets.length) {
      blocks.push(
        <ul key={`ul-${key}`} className="ml-4 list-disc space-y-1 marker:text-muted-foreground/60">
          {bullets.map((b, i) => (
            <li key={i} className="pl-1 leading-relaxed">{renderInline(b, `li-${key}-${i}`)}</li>
          ))}
        </ul>,
      );
      bullets = [];
    }
  };
  text.split("\n").forEach((raw, idx) => {
    const line = raw.trimEnd();
    const heading = line.match(/^#{1,4}\s+(.*)$/);
    const bullet = line.match(/^\s*(?:[-*]|\d+\.)\s+(.*)$/);
    if (heading) {
      flush(String(idx));
      blocks.push(
        <h4 key={`h-${idx}`} className="pt-2 text-[13px] font-semibold text-foreground first:pt-0">
          {heading[1]}
        </h4>,
      );
    } else if (bullet) {
      if (para.length) flush(String(idx));
      bullets.push(bullet[1]);
    } else if (!line.trim()) {
      flush(String(idx));
    } else {
      if (bullets.length) flush(String(idx));
      para.push(line.trim());
    }
  });
  flush("end");
  return <div className="space-y-2 text-[13px] text-muted-foreground">{blocks}</div>;
}

// ─── Diff viewer ───────────────────────────────────────────────────────

function DiffView({ diff }: { diff: string }) {
  if (!diff) return <p className="text-xs text-muted-foreground">No changes.</p>;
  const files = diff.split(/\n(?=--- )/);
  return (
    <div className="space-y-3">
      {files.map((chunk, fi) => {
        const lines = chunk.split("\n");
        const path = (lines.find((l) => l.startsWith("+++ ")) ?? "").replace(/^\+\+\+ (b\/)?/, "");
        const body = lines.filter((l) => !l.startsWith("--- ") && !l.startsWith("+++ "));
        return (
          <div key={fi} className="overflow-hidden rounded-lg border border-border/70">
            <div className="border-b border-border/70 bg-muted/40 px-3 py-1.5 font-mono text-[11px] text-muted-foreground">
              {path}
            </div>
            <div className="max-h-[380px] overflow-auto">
              <pre className="min-w-max font-mono text-xs leading-5">
                {body.map((line, i) => {
                  let cls = "px-3 ";
                  if (line.startsWith("@@")) cls += "bg-muted/30 text-muted-foreground/80";
                  else if (line.startsWith("+")) cls += "bg-emerald-500/10 text-emerald-900 dark:text-emerald-200";
                  else if (line.startsWith("-")) cls += "bg-red-500/10 text-red-900 dark:text-red-200";
                  else cls += "text-foreground/80";
                  return (
                    <div key={i} className={cls}>
                      {line || " "}
                    </div>
                  );
                })}
              </pre>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function AttemptBlock({
  attempt,
  isFinal,
  multiple,
}: {
  attempt: AttemptView;
  isFinal: boolean;
  multiple: boolean;
}) {
  // Latest attempt opens by default; a manual toggle wins after that.
  const [toggled, setToggled] = useState<boolean | null>(null);
  const open = toggled ?? isFinal;
  const v = attempt.validation;
  const verdict = !v ? (
    <span className="text-xs text-muted-foreground">Validating…</span>
  ) : v.passed ? (
    <span className="text-xs font-medium text-emerald-600 dark:text-emerald-400">Passed</span>
  ) : (
    <span className="text-xs font-medium text-red-600 dark:text-red-400">Rejected</span>
  );
  return (
    <div className="rounded-xl border border-border/70">
      <button
        type="button"
        onClick={() => setToggled(!open)}
        className="flex w-full items-center gap-2.5 px-4 py-3 text-left"
        aria-expanded={open}
      >
        {open ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        )}
        <span className="min-w-0 flex-1 truncate text-sm">
          {multiple && <span className="mr-2 text-muted-foreground">Attempt {attempt.attempt}</span>}
          {attempt.summary || "Proposed change"}
        </span>
        {verdict}
      </button>
      {open && (
        <div className="space-y-4 border-t border-border/70 px-4 py-4">
          {attempt.diff ? <DiffView diff={attempt.diff} /> : null}
          {v && (
            <div className="space-y-2">
              <p className={SECTION_LABEL}>Checks</p>
              <ul className="space-y-2">
                {v.checks.map((c, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-[13px]">
                    <span className="mt-0.5">
                      <StatusGlyph size="sm" state={c.status === "passed" ? "done" : c.status} />
                    </span>
                    <span className="min-w-0">
                      <span className="text-foreground">{c.name}</span>
                      <span className="block text-xs text-muted-foreground">{c.detail}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ItemDetail({ item, live }: { item: ItemView; live: boolean }) {
  const analysisRef = useRef<HTMLDivElement>(null);
  const analyzing = item.steps.analyze?.status === "running";
  useEffect(() => {
    if (analyzing && analysisRef.current) {
      analysisRef.current.scrollTop = analysisRef.current.scrollHeight;
    }
  }, [item.analysis, analyzing]);

  const analysisText = item.analysis.replace(/\n?\s*DECISION:\s*\w+\s*$/i, "");
  const lastAttempt = item.attempts[item.attempts.length - 1];

  return (
    <div className="space-y-8">
      <header className="space-y-2">
        <div className="flex flex-wrap items-center gap-3">
          <Severity severity={item.severity} />
          <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
            <StatusGlyph size="sm" state={itemGlyphState(item.status)} />
            {ITEM_STATUS_LABEL[item.status]}
          </span>
        </div>
        <h2 className="text-lg font-semibold tracking-tight">{item.title}</h2>
        {item.filePath && <p className="break-all font-mono text-xs text-muted-foreground">{item.filePath}</p>}
      </header>

      {item.reason && item.status !== "FIXED" && (
        <p
          className={`rounded-lg px-4 py-3 text-[13px] ${item.status === "FAILED" ? "bg-red-500/5 text-red-700 dark:text-red-300" : "bg-muted/50 text-muted-foreground"}`}
        >
          {item.reason}
        </p>
      )}

      <div className="grid gap-8 lg:grid-cols-[180px_minmax(0,1fr)]">
        {/* Vertical step timeline */}
        <ol className="relative space-y-4 self-start before:absolute before:bottom-2 before:left-[9px] before:top-2 before:w-px before:bg-border">
          {STEP_ORDER.map((s) => {
            const st = item.steps[s];
            return (
              <li key={s} className="relative flex gap-3" title={st?.message}>
                <span className="relative z-10 bg-card">
                  <StatusGlyph state={stepGlyphState(st?.status)} />
                </span>
                <span className="min-w-0 pt-0.5">
                  <span className={`block text-[13px] ${st ? "text-foreground" : "text-muted-foreground"}`}>
                    {STEP_LABELS[s]}
                  </span>
                  {st?.message && (
                    <span className="line-clamp-2 text-xs text-muted-foreground">{st.message}</span>
                  )}
                </span>
              </li>
            );
          })}
        </ol>

        <div className="min-w-0 space-y-8">
          {item.contextFiles.length > 0 && (
            <section className="space-y-2.5">
              <p className={SECTION_LABEL}>Files read</p>
              <div className="flex flex-wrap gap-1.5">
                {item.contextFiles.map((f) => (
                  <span
                    key={f.path}
                    className={`inline-flex max-w-full items-center gap-1.5 rounded-md px-2 py-1 font-mono text-[11px] ${f.primary ? "bg-foreground text-background" : "bg-muted text-muted-foreground"}`}
                  >
                    <span className="truncate">{f.path}</span>
                    <span className="opacity-60">{f.lines}</span>
                  </span>
                ))}
              </div>
              {item.contextReasoning && (
                <p className="text-xs text-muted-foreground">{item.contextReasoning}</p>
              )}
            </section>
          )}

          {(analysisText || analyzing) && (
            <section className="space-y-2.5">
              <p className={`${SECTION_LABEL} flex items-center gap-1.5`}>
                <Sparkles className="h-3 w-3" aria-hidden /> Reasoning
              </p>
              <div ref={analysisRef} className="max-h-[340px] overflow-y-auto rounded-xl bg-muted/40 px-5 py-4">
                <MarkdownLite text={analysisText} />
                {analyzing && live && (
                  <span className="ml-0.5 inline-block h-3.5 w-1 animate-pulse rounded-sm bg-foreground/50 align-middle" aria-hidden />
                )}
              </div>
            </section>
          )}

          {item.attempts.length > 0 && (
            <section className="space-y-2.5">
              <div className="flex items-center justify-between">
                <p className={SECTION_LABEL}>{item.status === "FIXED" ? "Change" : "Proposed changes"}</p>
                {item.commitSha && (
                  <span className="inline-flex items-center gap-1 font-mono text-[11px] text-muted-foreground">
                    <GitBranch className="h-3 w-3" aria-hidden /> {item.commitSha.slice(0, 8)}
                  </span>
                )}
              </div>
              <div className="space-y-2">
                {item.attempts.map((a) => (
                  <AttemptBlock
                    key={a.attempt}
                    attempt={a}
                    isFinal={a === lastAttempt}
                    multiple={item.attempts.length > 1}
                  />
                ))}
              </div>
            </section>
          )}

          {item.status === "PENDING" && (
            <p className="text-[13px] text-muted-foreground">
              Queued — the agent works through issues one at a time.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main view ─────────────────────────────────────────────────────────

function useElapsed(startIso: string | null, endIso: string | null): string {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!startIso || endIso) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [startIso, endIso]);
  if (!startIso) return "";
  const ms = (endIso ? new Date(endIso).getTime() : now) - new Date(startIso).getTime();
  const s = Math.max(0, Math.round(ms / 1000));
  return s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`;
}

function repoLabel(url: string | null): string | null {
  if (!url) return null;
  try {
    const u = new URL(url);
    return u.pathname.replace(/^\/+|\.git$/g, "").replace("/_git/", "/");
  } catch {
    return url;
  }
}

export function RemediationRunView({ initial }: { initial: RemediationRunSnapshot }) {
  const [snapshot, setSnapshot] = useState(initial);
  const [view, setView] = useState<RunView>(() => initialRunView(initial));
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [followLive, setFollowLive] = useState(true);
  const [cancelling, setCancelling] = useState(false);
  const [logOpen, setLogOpen] = useState(false);
  const [streamDone, setStreamDone] = useState(false);

  // Tail the event log. EventSource resumes via Last-Event-ID on reconnect;
  // the reducer ignores anything already applied.
  useEffect(() => {
    const es = new EventSource(`/api/remediation/runs/${initial.id}/stream`);
    const refresh = () =>
      fetch(`/api/remediation/runs/${initial.id}`)
        .then((r) => (r.ok ? r.json() : null))
        .then((s: RemediationRunSnapshot | null) => {
          if (s) setSnapshot(s);
        })
        .catch(() => undefined);
    es.onmessage = (msg) => {
      try {
        const e = JSON.parse(msg.data) as RemediationStreamEvent;
        setView((v) => applyRunEvent(v, e));
        if (e.type === "run_done" || e.type === "run_started") void refresh();
      } catch {
        /* ignore malformed frame */
      }
    };
    es.addEventListener("end", () => {
      es.close();
      setStreamDone(true);
      void refresh();
    });
    return () => es.close();
  }, [initial.id]);

  const status = view.status;
  const terminal = TERMINAL_RUN_STATUSES.has(status) || TERMINAL_RUN_STATUSES.has(snapshot.status);
  const effectiveStatus =
    TERMINAL_RUN_STATUSES.has(snapshot.status) && !TERMINAL_RUN_STATUSES.has(status) ? snapshot.status : status;
  const statusStyle = RUN_STATUS[effectiveStatus] ?? RUN_STATUS.QUEUED;
  const prUrl = view.prUrl ?? snapshot.prUrl;
  const prNumber = view.prNumber ?? snapshot.prNumber;
  const error = view.error ?? (terminal ? snapshot.errorMessage : null);
  const repo = repoLabel(view.repoUrl ?? snapshot.repoUrl);
  const headBranch = view.headBranch ?? snapshot.headBranch;
  const baseBranch = view.baseBranch ?? snapshot.baseBranch;

  const total = view.items.length;
  const done = view.counts.fixed + view.counts.failed + view.counts.skipped;
  const progress = total ? Math.round((done / total) * 100) : 0;
  const elapsed = useElapsed(snapshot.startedAt ?? snapshot.createdAt, snapshot.completedAt);
  const leftOut = view.counts.failed + view.counts.skipped;

  const shownId = followLive
    ? (view.currentItemId ?? selectedId ?? view.items[0]?.id ?? null)
    : selectedId;
  const shownItem = useMemo(
    () => view.items.find((i) => i.id === shownId) ?? view.items[0],
    [view.items, shownId],
  );

  async function cancel() {
    if (!window.confirm("Stop the remediation run? Nothing will be pushed.")) return;
    setCancelling(true);
    try {
      const res = await fetch(`/api/remediation/runs/${initial.id}/cancel`, { method: "POST" });
      const j = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(j.error || "Could not cancel");
      toast.success("Cancelling — the agent stops after the current step");
      if (snapshot.status === "QUEUED") {
        setSnapshot((s) => ({ ...s, status: "CANCELLED" }));
        setView((v) => ({ ...v, status: "CANCELLED" }));
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not cancel");
      setCancelling(false);
    }
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <header className="space-y-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-semibold tracking-tight">AI Remediation</h1>
              <span className={`inline-flex items-center gap-1.5 text-sm ${statusStyle.text}`}>
                <span className={`h-2 w-2 rounded-full ${statusStyle.dot}`} aria-hidden />
                {statusStyle.label}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px] text-muted-foreground">
              {repo && <span className="break-all">{repo}</span>}
              {view.provider && <span>· {PROVIDER_NAMES[view.provider] ?? view.provider}</span>}
              {baseBranch && (
                <span className="inline-flex items-center gap-1">
                  ·
                  <GitBranch className="h-3 w-3" aria-hidden />
                  <span className="font-mono text-xs">{headBranch ? `${headBranch} → ${baseBranch}` : baseBranch}</span>
                </span>
              )}
              {view.model && <span>· {view.model}</span>}
              {elapsed && <span className="tabular-nums">· {elapsed}</span>}
            </div>
          </div>
          {!terminal && (
            <Button variant="ghost" size="sm" onClick={cancel} disabled={cancelling || snapshot.cancelRequested}>
              {cancelling || snapshot.cancelRequested ? "Cancelling…" : "Cancel run"}
            </Button>
          )}
        </div>

        <div className="space-y-2">
          <div className="h-1 w-full overflow-hidden rounded-full bg-muted" role="progressbar" aria-valuenow={progress} aria-valuemin={0} aria-valuemax={100} aria-label="Remediation progress">
            <div className="h-full rounded-full bg-foreground transition-all duration-500" style={{ width: `${progress}%` }} />
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
            <span className="tabular-nums">{done} of {total} processed</span>
            <span className="tabular-nums"><span className="text-foreground">{view.counts.fixed}</span> fixed</span>
            <span className="tabular-nums"><span className="text-foreground">{view.counts.failed}</span> not fixed</span>
            <span className="tabular-nums"><span className="text-foreground">{view.counts.skipped}</span> skipped</span>
          </div>
        </div>
      </header>

      {/* Outcome */}
      {status === "QUEUED" && !terminal && (
        <div className="flex items-center gap-2.5 rounded-xl border border-border/70 px-5 py-4 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          Waiting for a worker to pick up this run…
        </div>
      )}
      {view.pushing && !prUrl && !terminal && (
        <div className="flex items-center gap-2.5 rounded-xl border border-border/70 px-5 py-4 text-sm">
          <Loader2 className="h-4 w-4 animate-spin text-blue-500" aria-hidden />
          All issues processed — pushing the branch and opening the pull request…
        </div>
      )}
      {prUrl && (
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border/70 bg-card px-5 py-4 shadow-sm">
          <div className="flex items-center gap-4">
            <span className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
              <GitPullRequest className="h-5 w-5" aria-hidden />
            </span>
            <div>
              <p className="font-medium">Pull request {prNumber ? `#${prNumber} ` : ""}is ready for review</p>
              <p className="text-[13px] text-muted-foreground">
                {view.counts.fixed} validated fix{view.counts.fixed === 1 ? "" : "es"}, one commit each
                {leftOut > 0 ? ` · ${leftOut} issue${leftOut === 1 ? "" : "s"} not included` : ""}
              </p>
            </div>
          </div>
          <Button asChild>
            <a href={prUrl} target="_blank" rel="noopener noreferrer">
              Review pull request
              <ArrowUpRight className="ml-1 h-4 w-4" aria-hidden />
            </a>
          </Button>
        </div>
      )}
      {terminal && !prUrl && error && (
        <p
          className={`rounded-xl px-5 py-4 text-sm ${effectiveStatus === "COMPLETED" ? "bg-muted/50 text-muted-foreground" : "bg-red-500/5 text-red-700 dark:text-red-300"}`}
        >
          {error}
        </p>
      )}

      {/* Issues + detail */}
      <div className="grid min-w-0 gap-6 xl:grid-cols-[300px_minmax(0,1fr)]">
        <nav aria-label="Issues" className="min-w-0 space-y-3">
          <div className="flex items-center justify-between">
            <p className={SECTION_LABEL}>Issues</p>
            {!terminal && (
              <button
                type="button"
                className={`text-xs transition-colors ${followLive ? "text-foreground" : "text-muted-foreground hover:text-foreground"}`}
                onClick={() => setFollowLive((f) => !f)}
              >
                {followLive ? "Following live" : "Follow live"}
              </button>
            )}
          </div>
          <ul className="overflow-hidden rounded-xl border border-border/70">
            {view.items.map((item) => {
              const active = shownItem?.id === item.id;
              return (
                <li key={item.id} className="border-b border-border/60 last:border-b-0">
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedId(item.id);
                      setFollowLive(false);
                    }}
                    className={`flex w-full items-start gap-3 px-4 py-3 text-left transition-colors ${active ? "bg-muted shadow-[inset_2px_0_0_0_var(--foreground)]" : "hover:bg-muted/40"}`}
                    aria-current={active ? "true" : undefined}
                  >
                    <span className="mt-0.5">
                      <StatusGlyph size="sm" state={itemGlyphState(item.status)} />
                    </span>
                    <span className="min-w-0 flex-1 space-y-1">
                      <span className="line-clamp-2 block text-[13px] font-medium leading-snug">{item.title}</span>
                      <span className="flex items-center gap-2">
                        <Severity severity={item.severity} />
                        {item.filePath && (
                          <span className="truncate font-mono text-[11px] text-muted-foreground/80">
                            {item.filePath.split("/").pop()}
                          </span>
                        )}
                      </span>
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        <section className="min-w-0 rounded-xl border border-border/70 bg-card p-6 sm:p-8" aria-live="polite">
          {shownItem ? (
            <ItemDetail item={shownItem} live={!terminal && !streamDone} />
          ) : (
            <p className="text-sm text-muted-foreground">No issues in this run.</p>
          )}
        </section>
      </div>

      {/* Activity log */}
      <section>
        <button
          type="button"
          onClick={() => setLogOpen((o) => !o)}
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground transition-colors hover:text-foreground"
          aria-expanded={logOpen}
        >
          {logOpen ? <ChevronDown className="h-3.5 w-3.5" aria-hidden /> : <ChevronRight className="h-3.5 w-3.5" aria-hidden />}
          Activity log ({view.logs.length})
        </button>
        {logOpen && (
          <ol className="mt-3 max-h-80 space-y-1 overflow-y-auto rounded-xl bg-muted/40 px-5 py-4 font-mono text-[11px]">
            {view.logs.map((l) => (
              <li
                key={`${l.seq}-${l.message}`}
                className={l.level === "error" ? "text-red-600 dark:text-red-400" : l.level === "warn" ? "text-amber-600 dark:text-amber-400" : "text-muted-foreground"}
              >
                <span className="mr-3 opacity-50">{new Date(l.at).toLocaleTimeString()}</span>
                {l.message}
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  );
}
