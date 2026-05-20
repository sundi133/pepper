import { prisma } from "./prisma";
import { getOrgAzureDevOpsAuth } from "./azure-devops-connection";
import { azureGet, azurePatch, azurePost } from "./azure-devops-api";
import type { AzureDevOpsAuth } from "./azure-devops-api";
import { logger } from "./logger";
import {
  buildPrMarker,
  findExistingCommentId,
  renderPrSummary,
} from "./github-pr-summary";
import { postAzureInlineReview } from "./azure-devops-pr-inline";
import { postAzurePrStatus } from "./azure-devops-pr-status";

const log = logger.child({ module: "azure-devops-pr-comment" });

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

interface AzureCommentResource {
  id?: number;
  content?: string | null;
}

interface AzureThreadResource {
  id?: number;
  comments?: AzureCommentResource[];
  threadContext?: unknown;
}

interface AzureThreadListResponse {
  value?: AzureThreadResource[];
}

function buildReviewUrl(scanId: string): string | null {
  const base =
    process.env.NEXTAUTH_URL ||
    process.env.APP_URL ||
    process.env.NEXT_PUBLIC_APP_URL;
  if (!base) return null;
  return `${base.replace(/\/+$/, "")}/scans/${scanId}`;
}

/**
 * List **general** (non-inline) PR threads. ADO uses the same /threads
 * endpoint for both general PR discussion and inline review threads;
 * inline threads carry a non-null `threadContext` with a filePath. The
 * summary lives at PR level so we only consider threads with no context.
 */
async function listGeneralThreads(
  auth: AzureDevOpsAuth,
  projectName: string,
  repoId: string,
  prId: number,
): Promise<
  Array<{ threadId: number; commentId: number; body: string | null }>
> {
  const r = await azureGet<AzureThreadListResponse>(
    auth,
    `/${encodeURIComponent(projectName)}/_apis/git/repositories/${encodeURIComponent(repoId)}/pullRequests/${prId}/threads`,
  );
  if (!r.ok || !r.data?.value) return [];
  const out: Array<{
    threadId: number;
    commentId: number;
    body: string | null;
  }> = [];
  for (const t of r.data.value) {
    if (t.threadContext) continue; // skip inline threads
    const firstComment = t.comments?.[0];
    if (t.id != null && firstComment?.id != null) {
      out.push({
        threadId: t.id,
        commentId: firstComment.id,
        body: firstComment.content ?? null,
      });
    }
  }
  return out;
}

async function upsertSummaryThread(
  auth: AzureDevOpsAuth,
  projectName: string,
  repoId: string,
  prId: number,
  marker: string,
  body: string,
): Promise<{ ok: boolean; threadId?: number; message?: string }> {
  const existing = await listGeneralThreads(auth, projectName, repoId, prId);
  // findExistingCommentId works on `{id, body}` — adapt to the first
  // comment of each general thread (where the marker lives).
  const adapted = existing.map((e) => ({ id: e.threadId, body: e.body }));
  const existingThreadId = findExistingCommentId(adapted, marker);

  if (existingThreadId != null) {
    const match = existing.find((e) => e.threadId === existingThreadId);
    if (!match) {
      return {
        ok: false,
        message: "internal: matched thread id not in list",
      };
    }
    const r = await azurePatch<{ id?: number }>(
      auth,
      `/${encodeURIComponent(projectName)}/_apis/git/repositories/${encodeURIComponent(repoId)}/pullRequests/${prId}/threads/${match.threadId}/comments/${match.commentId}`,
      { content: body, parentCommentId: 0 },
    );
    if (!r.ok) {
      return { ok: false, message: r.raw?.slice(0, 200) };
    }
    return { ok: true, threadId: match.threadId };
  }

  const r = await azurePost<{ id?: number }>(
    auth,
    `/${encodeURIComponent(projectName)}/_apis/git/repositories/${encodeURIComponent(repoId)}/pullRequests/${prId}/threads`,
    {
      comments: [{ parentCommentId: 0, content: body, commentType: 1 }],
      status: 1, // active
    },
  );
  if (!r.ok) {
    return { ok: false, message: r.raw?.slice(0, 200) };
  }
  return { ok: true, threadId: r.data.id };
}

/**
 * Post (or update) the Pepper PR review on an Azure DevOps Services PR
 * for a completed webhook-triggered scan. Mirrors `postScanPrSummary`
 * (GitHub) and `postScanBitbucketPrSummary` (Bitbucket). Safe to call
 * always — silently skips when the scan was not webhook-triggered, has
 * no PR, no linked ADO repo, or no PAT is connected for the org.
 */
export async function postScanAzurePrSummary(scanId: string): Promise<void> {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      id: true,
      status: true,
      sourceType: true,
      prNumber: true,
      branch: true,
      commitSha: true,
      gateResult: true,
      errorMessage: true,
      criticalCount: true,
      highCount: true,
      mediumCount: true,
      lowCount: true,
      infoCount: true,
      project: {
        select: {
          id: true,
          name: true,
          organizationId: true,
          azureOrganization: true,
          azureProjectName: true,
          azureRepoId: true,
        },
      },
    },
  });

  if (!scan?.project) return;
  if (scan.sourceType !== "WEBHOOK") return;
  if (scan.prNumber == null) return;
  const {
    azureProjectName,
    azureRepoId,
    organizationId,
    id: projectId,
  } = scan.project;
  if (!azureProjectName || !azureRepoId) {
    log.debug(
      { scanId },
      "Azure DevOps PR summary skipped: project has no ADO project/repo",
    );
    return;
  }

  const auth = await getOrgAzureDevOpsAuth(organizationId);
  if (!auth) {
    log.info(
      { scanId, organizationId },
      "Azure DevOps PR summary skipped: no PAT for org",
    );
    return;
  }

  const status: "COMPLETED" | "FAILED" =
    scan.status === "COMPLETED" ? "COMPLETED" : "FAILED";

  const topFindings =
    status === "COMPLETED"
      ? await prisma.finding.findMany({
          where: { scanId, status: "OPEN" },
          select: {
            severity: true,
            title: true,
            description: true,
            filePath: true,
            startLine: true,
            ruleId: true,
            cweId: true,
          },
          take: 100,
        })
      : [];

  topFindings.sort(
    (a: { severity: string }, b: { severity: string }) =>
      (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99),
  );

  const marker = buildPrMarker(projectId);
  const reviewUrl = buildReviewUrl(scan.id);
  const body = renderPrSummary(
    {
      scanId: scan.id,
      projectName: scan.project.name,
      commitSha: scan.commitSha,
      branch: scan.branch,
      gateResult: scan.gateResult as "PENDING" | "PASSED" | "FAILED",
      counts: {
        critical: scan.criticalCount,
        high: scan.highCount,
        medium: scan.mediumCount,
        low: scan.lowCount,
        info: scan.infoCount,
      },
      topFindings: topFindings.slice(0, 10),
      reviewUrl,
      status,
      errorMessage: scan.errorMessage,
    },
    marker,
  );

  const result = await upsertSummaryThread(
    auth,
    azureProjectName,
    azureRepoId,
    scan.prNumber,
    marker,
    body,
  );

  if (!result.ok) {
    log.warn(
      {
        scanId,
        adoProject: azureProjectName,
        adoRepo: azureRepoId,
        msg: result.message,
      },
      "Failed to upsert Azure DevOps PR summary thread",
    );
  } else {
    log.info(
      {
        scanId,
        adoProject: azureProjectName,
        adoRepo: azureRepoId,
        prId: scan.prNumber,
        threadId: result.threadId,
      },
      "Posted Azure DevOps PR security review summary",
    );
  }

  if (status === "COMPLETED" && scan.commitSha && topFindings.length > 0) {
    try {
      const inline = await postAzureInlineReview({
        auth,
        projectName: azureProjectName,
        repoId: azureRepoId,
        prId: scan.prNumber,
        findings: topFindings,
        reviewUrl,
      });
      log.info(
        {
          scanId,
          prId: scan.prNumber,
          posted: inline.posted,
          skipped: inline.skipped,
        },
        "Azure DevOps inline review threads dispatched",
      );
    } catch (e) {
      log.warn(
        { scanId, e },
        "Azure DevOps inline review failed (non-blocking)",
      );
    }
  }

  if (scan.commitSha) {
    try {
      await postAzurePrStatus({
        auth,
        projectName: azureProjectName,
        repoId: azureRepoId,
        prId: scan.prNumber,
        scanStatus: status,
        gateResult: scan.gateResult as "PENDING" | "PASSED" | "FAILED",
        counts: {
          critical: scan.criticalCount,
          high: scan.highCount,
          medium: scan.mediumCount,
          low: scan.lowCount,
        },
        reviewUrl,
      });
    } catch (e) {
      log.warn(
        { scanId, e },
        "Azure DevOps PR status post failed (non-blocking)",
      );
    }
  }
}
