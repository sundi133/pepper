/**
 * `pepper/security` commit statuses on GitLab merge requests
 * (docs/PR_REVIEW_PROVIDERS_SPEC.md §2.5). Posted only when the connection has
 * them switched on: a failed status blocks merges under "Pipelines must succeed".
 */
import { gitlabPost, type GitLabAuth } from "./gitlab-api";
import { gitLabCommitStatusesEnabled } from "./gitlab-connection";
import { logger } from "./logger";

const log = logger.child({ module: "gitlab-commit-status" });

export const GITLAB_STATUS_NAME = "pepper/security";

export type GitLabStatusState = "pending" | "running" | "success" | "failed";

export async function postGitLabCommitStatus(input: {
  organizationId: string;
  auth: GitLabAuth;
  gitlabProjectId: number;
  sha: string;
  state: GitLabStatusState;
  description: string;
  targetUrl?: string | null;
}): Promise<void> {
  if (!/^[0-9a-f]{7,64}$/i.test(input.sha)) return;
  if (!(await gitLabCommitStatusesEnabled(input.organizationId))) return;
  const r = await gitlabPost(input.auth, `/projects/${input.gitlabProjectId}/statuses/${input.sha}`, {
    state: input.state,
    name: GITLAB_STATUS_NAME,
    description: input.description.slice(0, 255),
    ...(input.targetUrl ? { target_url: input.targetUrl } : {}),
  });
  // GitLab answers 400 when the status is already in that state; not worth a warning.
  if (!r.ok && r.status !== 400) {
    log.warn({ gitlabProjectId: input.gitlabProjectId, status: r.status }, "GitLab commit status failed");
  }
}

interface Counts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** The final status for a completed (or failed) scan, as on Azure DevOps. */
export function scanCommitStatus(
  scanStatus: "COMPLETED" | "FAILED",
  gateResult: string | null,
  c: Counts,
): { state: "success" | "failed"; description: string } {
  if (scanStatus === "FAILED") return { state: "failed", description: "Pepper scan failed" };
  const parts: string[] = [];
  if (c.critical) parts.push(`${c.critical} critical`);
  if (c.high) parts.push(`${c.high} high`);
  if (c.medium) parts.push(`${c.medium} medium`);
  if (c.low) parts.push(`${c.low} low`);
  const describe = (prefix: string) => (parts.length ? `${prefix}: ${parts.join(", ")}` : prefix);
  if (gateResult === "FAILED") return { state: "failed", description: describe("Build gate failed") };
  return { state: "success", description: parts.length ? describe("Build gate passed") : "No security findings" };
}
