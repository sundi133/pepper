/**
 * Client-side fold of the remediation event stream into a view model. Pure
 * so the UI can replay a finished run from its event log and so it is testable.
 */
import type {
  RemediationItemStatus,
  RemediationRunSnapshot,
  RemediationRunStatus,
  RemediationStep,
  RemediationStreamEvent,
  StepStatus,
  ValidationCheck,
} from "./types";

export const STEP_ORDER: RemediationStep[] = [
  "locate",
  "context",
  "analyze",
  "fix",
  "validate",
  "commit",
];

export interface AttemptView {
  attempt: number;
  summary: string;
  diff: string;
  files: string[];
  validation?: { passed: boolean; checks: ValidationCheck[] };
}

export interface ItemView {
  id: string;
  findingId: string;
  title: string;
  severity: string;
  filePath: string | null;
  status: RemediationItemStatus;
  steps: Partial<Record<RemediationStep, { status: StepStatus; message: string }>>;
  contextFiles: Array<{ path: string; lines: number; primary: boolean }>;
  contextReasoning: string;
  analysis: string;
  attempts: AttemptView[];
  reason?: string;
  commitSha?: string;
  finalDiff?: string;
}

export interface LogLine {
  seq: number;
  at: string;
  level: "info" | "warn" | "error";
  message: string;
  itemId?: string;
}

export interface RunView {
  status: RemediationRunStatus;
  provider: string | null;
  repoUrl: string | null;
  baseBranch: string | null;
  headBranch: string | null;
  model: string | null;
  items: ItemView[];
  currentItemId: string | null;
  logs: LogLine[];
  prUrl: string | null;
  prNumber: number | null;
  error: string | null;
  pushing: boolean;
  lastSeq: number;
  counts: { fixed: number; failed: number; skipped: number };
}

export function initialRunView(snapshot: RemediationRunSnapshot): RunView {
  const items: ItemView[] = snapshot.items.map((i) => ({
    id: i.id,
    findingId: i.findingId,
    title: i.title,
    severity: i.severity,
    filePath: i.filePath,
    status: i.status,
    steps: {},
    contextFiles: [],
    contextReasoning: "",
    analysis: "",
    attempts: [],
  }));
  return {
    status: snapshot.status,
    provider: snapshot.provider,
    repoUrl: snapshot.repoUrl,
    baseBranch: snapshot.baseBranch,
    headBranch: snapshot.headBranch,
    model: null,
    items,
    currentItemId: null,
    logs: [],
    prUrl: snapshot.prUrl,
    prNumber: snapshot.prNumber,
    error: snapshot.errorMessage,
    pushing: false,
    lastSeq: 0,
    counts: {
      fixed: items.filter((i) => i.status === "FIXED").length,
      failed: items.filter((i) => i.status === "FAILED").length,
      skipped: items.filter((i) => i.status === "SKIPPED").length,
    },
  };
}

function updateItem(
  view: RunView,
  itemId: string,
  fn: (item: ItemView) => ItemView,
): RunView {
  return {
    ...view,
    items: view.items.map((i) => (i.id === itemId ? fn(i) : i)),
  };
}

const STEP_TO_STATUS: Partial<Record<RemediationStep, RemediationItemStatus>> = {
  locate: "ANALYZING",
  context: "ANALYZING",
  analyze: "ANALYZING",
  fix: "FIXING",
  validate: "VALIDATING",
  commit: "VALIDATING",
};

function countItems(items: ItemView[]): RunView["counts"] {
  return {
    fixed: items.filter((i) => i.status === "FIXED").length,
    failed: items.filter((i) => i.status === "FAILED").length,
    skipped: items.filter((i) => i.status === "SKIPPED").length,
  };
}

export function applyRunEvent(view: RunView, e: RemediationStreamEvent): RunView {
  if (e.seq <= view.lastSeq) return view;
  let next: RunView = { ...view, lastSeq: e.seq };
  const log = (level: LogLine["level"], message: string, itemId?: string) => {
    next = {
      ...next,
      logs: [...next.logs, { seq: e.seq, at: e.at, level, message, itemId }].slice(-500),
    };
  };

  switch (e.type) {
    case "run_started":
      next = {
        ...next,
        status: "RUNNING",
        provider: e.provider,
        repoUrl: e.repoUrl,
        baseBranch: e.baseBranch,
        headBranch: e.headBranch,
        model: e.model,
      };
      log("info", `Working on ${e.total} issue${e.total === 1 ? "" : "s"} with ${e.model}`);
      break;
    case "log":
      if (next.status === "QUEUED") next = { ...next, status: "RUNNING" };
      log(e.level, e.message);
      break;
    case "item_started":
      next = updateItem({ ...next, currentItemId: e.itemId }, e.itemId, (i) => ({
        ...i,
        status: "ANALYZING",
      }));
      log("info", `Issue ${e.index + 1}: ${e.title}`, e.itemId);
      break;
    case "step": {
      next = updateItem(next, e.itemId, (i) => {
        const nextStatus =
          e.status === "running" ? (STEP_TO_STATUS[e.step] ?? i.status) : i.status;
        // A retry re-enters "fix": clear later steps from the previous attempt.
        const steps = { ...i.steps };
        if (e.step === "fix" && e.status === "running") {
          delete steps.validate;
          delete steps.commit;
        }
        steps[e.step] = { status: e.status, message: e.message };
        return { ...i, status: nextStatus, steps };
      });
      if (e.status !== "running") {
        log(e.status === "failed" ? "warn" : "info", e.message, e.itemId);
      }
      break;
    }
    case "context":
      next = updateItem(next, e.itemId, (i) => ({
        ...i,
        contextFiles: e.files,
        contextReasoning: e.reasoning,
      }));
      break;
    case "analysis_delta":
      next = updateItem(next, e.itemId, (i) => ({ ...i, analysis: i.analysis + e.text }));
      break;
    case "fix_proposed":
      next = updateItem(next, e.itemId, (i) => ({
        ...i,
        attempts: [
          ...i.attempts.filter((a) => a.attempt !== e.attempt),
          { attempt: e.attempt, summary: e.summary, diff: e.diff, files: e.files },
        ],
      }));
      break;
    case "validation":
      next = updateItem(next, e.itemId, (i) => {
        const existing = i.attempts.find((a) => a.attempt === e.attempt);
        const validation = { passed: e.passed, checks: e.checks };
        const attempts = existing
          ? i.attempts.map((a) => (a.attempt === e.attempt ? { ...a, validation } : a))
          : [...i.attempts, { attempt: e.attempt, summary: "", diff: "", files: [], validation }];
        return { ...i, attempts };
      });
      break;
    case "item_done":
      next = updateItem(next, e.itemId, (i) => ({
        ...i,
        status: e.status,
        reason: e.reason,
        commitSha: e.commitSha,
        finalDiff: e.diff,
      }));
      next = { ...next, counts: countItems(next.items) };
      log(
        e.status === "FIXED" ? "info" : "warn",
        `${e.status === "FIXED" ? "Fixed" : e.status === "SKIPPED" ? "Skipped" : "Not fixed"}: ${e.reason}`,
        e.itemId,
      );
      break;
    case "pr_opening":
      next = { ...next, pushing: true, headBranch: e.branch };
      break;
    case "run_done":
      next = {
        ...next,
        status: e.status,
        pushing: false,
        prUrl: e.prUrl ?? next.prUrl,
        prNumber: e.prNumber ?? next.prNumber,
        error: e.error ?? null,
        currentItemId: null,
        counts: { fixed: e.fixed, failed: e.failed, skipped: e.skipped },
      };
      if (e.prUrl) log("info", `Pull request opened: ${e.prUrl}`);
      else if (e.error) log(e.status === "COMPLETED" ? "info" : "error", e.error);
      break;
  }
  return next;
}
