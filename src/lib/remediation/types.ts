/**
 * Shared (client + server) shapes for AI remediation runs and the event
 * stream the UI renders. Keep this file free of server-only imports.
 */

export type RemediationRunStatus =
  | "QUEUED"
  | "RUNNING"
  | "COMPLETED"
  | "PARTIAL"
  | "FAILED"
  | "CANCELLED";

export type RemediationItemStatus =
  | "PENDING"
  | "ANALYZING"
  | "FIXING"
  | "VALIDATING"
  | "FIXED"
  | "FAILED"
  | "SKIPPED";

export type RemediationStep =
  | "locate"
  | "context"
  | "analyze"
  | "fix"
  | "validate"
  | "commit";

export type StepStatus = "running" | "done" | "failed" | "skipped";

export interface ValidationCheck {
  name: string;
  status: "passed" | "failed" | "skipped";
  detail: string;
}

export type RemediationEventPayload =
  | {
      type: "run_started";
      total: number;
      provider: string;
      repoUrl: string;
      baseBranch: string;
      headBranch: string;
      model: string;
    }
  | { type: "log"; level: "info" | "warn" | "error"; message: string }
  | {
      type: "item_started";
      itemId: string;
      index: number;
      title: string;
      filePath: string | null;
    }
  | {
      type: "step";
      itemId: string;
      step: RemediationStep;
      status: StepStatus;
      message: string;
    }
  | {
      type: "context";
      itemId: string;
      files: Array<{ path: string; lines: number; primary: boolean }>;
      reasoning: string;
    }
  | { type: "analysis_delta"; itemId: string; text: string }
  | {
      type: "fix_proposed";
      itemId: string;
      attempt: number;
      summary: string;
      diff: string;
      files: string[];
    }
  | {
      type: "validation";
      itemId: string;
      attempt: number;
      passed: boolean;
      checks: ValidationCheck[];
    }
  | {
      type: "item_done";
      itemId: string;
      status: "FIXED" | "FAILED" | "SKIPPED";
      reason: string;
      diff?: string;
      commitSha?: string;
    }
  | { type: "pr_opening"; branch: string; commits: number }
  | {
      type: "run_done";
      status: RemediationRunStatus;
      fixed: number;
      failed: number;
      skipped: number;
      prUrl?: string;
      prNumber?: number | null;
      error?: string;
    };

export type RemediationEventType = RemediationEventPayload["type"];

/** A persisted event as sent over SSE. */
export type RemediationStreamEvent = RemediationEventPayload & {
  seq: number;
  at: string;
};

export const TERMINAL_RUN_STATUSES: ReadonlySet<RemediationRunStatus> = new Set([
  "COMPLETED",
  "PARTIAL",
  "FAILED",
  "CANCELLED",
]);

/** Most findings a single run may take — keeps one PR reviewable. */
export const MAX_FINDINGS_PER_RUN = 25;

export interface RemediationRunSnapshot {
  id: string;
  scanId: string;
  status: RemediationRunStatus;
  provider: string | null;
  repoUrl: string | null;
  baseBranch: string | null;
  headBranch: string | null;
  prUrl: string | null;
  prNumber: number | null;
  errorMessage: string | null;
  fixedCount: number;
  failedCount: number;
  cancelRequested: boolean;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  items: Array<{
    id: string;
    findingId: string;
    position: number;
    status: RemediationItemStatus;
    title: string;
    severity: string;
    filePath: string | null;
  }>;
}
