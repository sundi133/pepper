import { azurePost } from "./azure-devops-api";
import type { AzureDevOpsAuth } from "./azure-devops-api";
import { logger } from "./logger";

const log = logger.child({ module: "azure-devops-pr-status" });

const STATUS_CONTEXT_NAME = "security";
const STATUS_CONTEXT_GENRE = "pepper";

type GateResult = "PENDING" | "PASSED" | "FAILED";
type ScanStatus = "COMPLETED" | "FAILED";

export interface SeverityCountsLite {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/**
 * Azure DevOps PR status. Surfaced on the PR header next to required
 * checks. State values per the ADO docs: notSet=0, pending=1,
 * succeeded=2, failed=3, notApplicable=4. ADO accepts both numeric and
 * string forms; we send the string form because it's self-documenting
 * in logs and audit trails.
 */
export async function postAzurePrStatus(input: {
  auth: AzureDevOpsAuth;
  projectName: string;
  repoId: string;
  prId: number;
  scanStatus: ScanStatus;
  gateResult: GateResult;
  counts: SeverityCountsLite;
  reviewUrl: string | null;
}): Promise<void> {
  const {
    auth,
    projectName,
    repoId,
    prId,
    scanStatus,
    gateResult,
    counts,
    reviewUrl,
  } = input;

  let state: "succeeded" | "failed";
  let description: string;

  if (scanStatus === "FAILED") {
    state = "failed";
    description = "Pepper scan failed";
  } else if (gateResult === "FAILED") {
    state = "failed";
    description = describeCounts("Build gate failed", counts);
  } else {
    state = "succeeded";
    description =
      counts.critical + counts.high + counts.medium + counts.low === 0
        ? "No security findings"
        : describeCounts("Build gate passed", counts);
  }

  const r = await azurePost(
    auth,
    `/${encodeURIComponent(projectName)}/_apis/git/repositories/${encodeURIComponent(repoId)}/pullRequests/${prId}/statuses`,
    {
      state,
      description: description.slice(0, 140),
      targetUrl: reviewUrl ?? undefined,
      context: { name: STATUS_CONTEXT_NAME, genre: STATUS_CONTEXT_GENRE },
    },
  );

  if (!r.ok) {
    log.warn(
      {
        projectName,
        repoId,
        prId,
        status: r.status,
        raw: r.raw?.slice(0, 200),
      },
      "Failed to post Azure DevOps PR status",
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
