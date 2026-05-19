import { githubPost } from "./github-api";
import { logger } from "./logger";

const log = logger.child({ module: "github-pr-status" });

const STATUS_CONTEXT = "pepper/security";

type GateResult = "PENDING" | "PASSED" | "FAILED";
type ScanStatus = "COMPLETED" | "FAILED";

export interface SeverityCountsLite {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/**
 * GitHub Check Runs require GitHub App authentication, which Pepper does
 * not yet have — orgs connect via user OAuth (scope `repo`). Commit
 * Statuses (`POST /statuses/{sha}`) work with `repo` scope and show up in
 * the same "Checks" section of the PR header, so we use them as the
 * pass/fail signal.
 */
export async function postCommitStatus(input: {
  token: string;
  owner: string;
  repo: string;
  sha: string;
  scanStatus: ScanStatus;
  gateResult: GateResult;
  counts: SeverityCountsLite;
  reviewUrl: string | null;
}): Promise<void> {
  const { token, owner, repo, sha, scanStatus, gateResult, counts, reviewUrl } =
    input;

  let state: "success" | "failure" | "error";
  let description: string;

  if (scanStatus === "FAILED") {
    state = "error";
    description = "Pepper scan failed";
  } else if (gateResult === "FAILED") {
    state = "failure";
    description = describeCounts("Build gate failed", counts);
  } else {
    state = "success";
    description =
      counts.critical + counts.high + counts.medium + counts.low === 0
        ? "No security findings"
        : describeCounts("Build gate passed", counts);
  }

  const r = await githubPost<{ message?: string }>(
    token,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/statuses/${encodeURIComponent(sha)}`,
    {
      state,
      context: STATUS_CONTEXT,
      description: description.slice(0, 140),
      target_url: reviewUrl ?? undefined,
    },
  );

  if (!r.ok) {
    log.warn(
      { owner, repo, sha, status: r.status, msg: r.data?.message || r.raw?.slice(0, 200) },
      "Failed to post commit status",
    );
  }
}

function describeCounts(prefix: string, c: SeverityCountsLite): string {
  const parts: string[] = [];
  if (c.critical) parts.push(`${c.critical} critical`);
  if (c.high) parts.push(`${c.high} high`);
  if (c.medium) parts.push(`${c.medium} medium`);
  if (c.low) parts.push(`${c.low} low`);
  return parts.length ? `${prefix} — ${parts.join(", ")}` : prefix;
}
