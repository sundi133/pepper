import { bitbucketPost } from "./bitbucket-api";
import type { BitbucketAuth } from "./bitbucket-api";
import { logger } from "./logger";

const log = logger.child({ module: "bitbucket-pr-status" });

const STATUS_KEY = "pepper-security";
const STATUS_NAME = "Pepper security";

type GateResult = "PENDING" | "PASSED" | "FAILED";
type ScanStatus = "COMPLETED" | "FAILED";

export interface SeverityCountsLite {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/**
 * Bitbucket Cloud commit build status. Shows up on the PR header next to
 * other CI checks. Three states recognised by Bitbucket: SUCCESSFUL,
 * FAILED, INPROGRESS, STOPPED. We never post INPROGRESS here because we
 * only run after the scan finishes.
 */
export async function postBitbucketCommitStatus(input: {
  auth: BitbucketAuth;
  workspace: string;
  repoSlug: string;
  sha: string;
  scanStatus: ScanStatus;
  gateResult: GateResult;
  counts: SeverityCountsLite;
  reviewUrl: string | null;
}): Promise<void> {
  const {
    auth,
    workspace,
    repoSlug,
    sha,
    scanStatus,
    gateResult,
    counts,
    reviewUrl,
  } = input;

  let state: "SUCCESSFUL" | "FAILED";
  let description: string;

  if (scanStatus === "FAILED") {
    state = "FAILED";
    description = "Pepper scan failed";
  } else if (gateResult === "FAILED") {
    state = "FAILED";
    description = describeCounts("Build gate failed", counts);
  } else {
    state = "SUCCESSFUL";
    description =
      counts.critical + counts.high + counts.medium + counts.low === 0
        ? "No security findings"
        : describeCounts("Build gate passed", counts);
  }

  if (!reviewUrl) {
    // Bitbucket build statuses require a non-empty url; nothing useful to
    // link to without NEXTAUTH_URL configured, so skip rather than post
    // a broken link.
    log.info(
      { workspace, repoSlug, sha },
      "Bitbucket build status skipped: no review URL (NEXTAUTH_URL unset)",
    );
    return;
  }

  const r = await bitbucketPost(
    auth,
    `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/commit/${encodeURIComponent(sha)}/statuses/build`,
    {
      key: STATUS_KEY,
      state,
      name: STATUS_NAME,
      url: reviewUrl,
      description: description.slice(0, 140),
    },
  );

  if (!r.ok) {
    log.warn(
      { workspace, repoSlug, sha, status: r.status, raw: r.raw?.slice(0, 200) },
      "Failed to post Bitbucket build status",
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

/**
 * A status before the scan finishes (docs/PR_REVIEW_PROVIDERS_SPEC.md §3.4):
 * INPROGRESS while a review is queued (or waits for a collaborator), SUCCESSFUL
 * for a deliberate skip. Uses the same key, so the final status replaces it.
 */
export async function postBitbucketSimpleStatus(input: {
  auth: BitbucketAuth;
  workspace: string;
  repoSlug: string;
  sha: string;
  state: "INPROGRESS" | "SUCCESSFUL";
  description: string;
  url: string | null;
}): Promise<void> {
  // Bitbucket requires a link (see above).
  if (!input.url) return;
  const r = await bitbucketPost(
    input.auth,
    `/repositories/${encodeURIComponent(input.workspace)}/${encodeURIComponent(input.repoSlug)}/commit/${encodeURIComponent(input.sha)}/statuses/build`,
    { key: STATUS_KEY, state: input.state, name: STATUS_NAME, url: input.url, description: input.description.slice(0, 140) },
  );
  if (!r.ok) log.warn({ workspace: input.workspace, repoSlug: input.repoSlug, status: r.status }, "Bitbucket build status failed");
}
