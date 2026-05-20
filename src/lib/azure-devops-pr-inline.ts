import { azureGet, azurePost } from "./azure-devops-api";
import type { AzureDevOpsAuth } from "./azure-devops-api";
import { logger } from "./logger";
import {
  buildFindingMarker,
  buildInlineCommentBody,
  extractFindingMarkers,
  parseAzureChangedFiles,
  type AzureIterationChangesResponse,
  type InlineFinding,
} from "./azure-devops-pr-inline-format";

const log = logger.child({ module: "azure-devops-pr-inline" });

const MAX_INLINE_COMMENTS_PER_REVIEW = 30;

interface AzureIteration {
  id?: number;
}

interface AzureIterationListResponse {
  count?: number;
  value?: AzureIteration[];
}

interface AzureComment {
  content?: string | null;
}

interface AzureThread {
  id?: number;
  comments?: AzureComment[];
  threadContext?: {
    filePath?: string | null;
    rightFileStart?: { line?: number | null } | null;
  } | null;
}

interface AzureThreadListResponse {
  value?: AzureThread[];
}

async function fetchLatestIterationId(
  auth: AzureDevOpsAuth,
  projectName: string,
  repoId: string,
  prId: number,
): Promise<number | null> {
  const r = await azureGet<AzureIterationListResponse>(
    auth,
    `/${encodeURIComponent(projectName)}/_apis/git/repositories/${encodeURIComponent(repoId)}/pullRequests/${prId}/iterations`,
  );
  if (!r.ok) {
    log.warn(
      { projectName, repoId, prId, status: r.status },
      "Failed to list PR iterations",
    );
    return null;
  }
  const iterations = r.data.value ?? [];
  if (iterations.length === 0) return null;
  // Iterations are returned in chronological order; the last is the most recent.
  const latest = iterations[iterations.length - 1];
  return latest.id ?? null;
}

async function fetchChangedFiles(
  auth: AzureDevOpsAuth,
  projectName: string,
  repoId: string,
  prId: number,
): Promise<Set<string>> {
  const iterationId = await fetchLatestIterationId(
    auth,
    projectName,
    repoId,
    prId,
  );
  if (iterationId == null) return new Set();
  const r = await azureGet<AzureIterationChangesResponse>(
    auth,
    `/${encodeURIComponent(projectName)}/_apis/git/repositories/${encodeURIComponent(repoId)}/pullRequests/${prId}/iterations/${iterationId}/changes`,
  );
  if (!r.ok) {
    log.warn(
      { projectName, repoId, prId, iterationId, status: r.status },
      "Failed to fetch iteration changes",
    );
    return new Set();
  }
  return parseAzureChangedFiles(r.data);
}

async function fetchExistingThreadMarkers(
  auth: AzureDevOpsAuth,
  projectName: string,
  repoId: string,
  prId: number,
): Promise<Set<string>> {
  const seen = new Set<string>();
  const r = await azureGet<AzureThreadListResponse>(
    auth,
    `/${encodeURIComponent(projectName)}/_apis/git/repositories/${encodeURIComponent(repoId)}/pullRequests/${prId}/threads`,
  );
  if (!r.ok || !r.data?.value) {
    return seen;
  }
  for (const thread of r.data.value) {
    for (const comment of thread.comments ?? []) {
      for (const m of extractFindingMarkers(comment.content ?? null)) {
        seen.add(m);
      }
    }
  }
  return seen;
}

export interface PostAzureInlineReviewInput {
  auth: AzureDevOpsAuth;
  projectName: string;
  repoId: string;
  prId: number;
  findings: InlineFinding[];
  reviewUrl: string | null;
}

/**
 * Post inline review threads on an Azure DevOps PR.
 *
 * Strategy:
 *   1. Fetch the PR's latest iteration → list of changed file paths.
 *   2. Fetch existing threads → set of `pepper-finding:<hash>` markers
 *      already on the PR (so we don't duplicate on re-runs).
 *   3. Filter findings to ones where (a) filePath is in the changed set,
 *      (b) startLine is present, (c) marker not already on the PR. Cap
 *      to MAX_INLINE_COMMENTS_PER_REVIEW per scan.
 *   4. POST one thread per picked finding with right-side line context.
 */
export async function postAzureInlineReview(
  input: PostAzureInlineReviewInput,
): Promise<{ posted: number; skipped: number }> {
  const { auth, projectName, repoId, prId, findings, reviewUrl } = input;

  const [changedFiles, existingMarkers] = await Promise.all([
    fetchChangedFiles(auth, projectName, repoId, prId),
    fetchExistingThreadMarkers(auth, projectName, repoId, prId),
  ]);

  if (changedFiles.size === 0) {
    return { posted: 0, skipped: findings.length };
  }

  const picked: Array<{ finding: InlineFinding; line: number }> = [];
  for (const f of findings) {
    if (picked.length >= MAX_INLINE_COMMENTS_PER_REVIEW) break;
    if (!f.filePath || f.startLine == null) continue;
    const normalisedPath = f.filePath.replace(/^\/+/, "");
    if (!changedFiles.has(normalisedPath)) continue;
    if (existingMarkers.has(buildFindingMarker(f))) continue;
    picked.push({ finding: f, line: f.startLine });
  }

  if (picked.length === 0) {
    return { posted: 0, skipped: findings.length };
  }

  let posted = 0;
  for (const p of picked) {
    const body = buildInlineCommentBody(p.finding, { reviewUrl });
    const r = await azurePost(
      auth,
      `/${encodeURIComponent(projectName)}/_apis/git/repositories/${encodeURIComponent(repoId)}/pullRequests/${prId}/threads`,
      {
        comments: [{ parentCommentId: 0, content: body, commentType: 1 }],
        status: 1, // active
        threadContext: {
          filePath: `/${(p.finding.filePath ?? "").replace(/^\/+/, "")}`,
          rightFileStart: { line: p.line, offset: 1 },
          rightFileEnd: { line: p.line, offset: 1 },
        },
      },
    );
    if (r.ok) {
      posted++;
    } else {
      log.warn(
        {
          projectName,
          repoId,
          prId,
          path: p.finding.filePath,
          line: p.line,
          status: r.status,
        },
        "Failed to post ADO inline thread",
      );
    }
  }

  return { posted, skipped: findings.length - posted };
}
