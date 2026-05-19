import { prisma } from "./prisma";
import { getOrgGithubAccessToken } from "./github-connection";
import { githubGet, githubPost, githubPatch } from "./github-api";
import { logger } from "./logger";
import {
  buildPrMarker,
  findExistingCommentId,
  renderPrSummary,
} from "./github-pr-summary";
import { postInlineReview } from "./github-pr-inline";
import { postCommitStatus } from "./github-pr-status";

const log = logger.child({ module: "github-pr-comment" });

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

interface IssueComment {
  id: number;
  body?: string | null;
}

function buildReviewUrl(scanId: string): string | null {
  const base =
    process.env.NEXTAUTH_URL ||
    process.env.APP_URL ||
    process.env.NEXT_PUBLIC_APP_URL;
  if (!base) return null;
  return `${base.replace(/\/+$/, "")}/scans/${scanId}`;
}

async function listIssueComments(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<IssueComment[]> {
  const all: IssueComment[] = [];
  for (let page = 1; page <= 10; page++) {
    const r = await githubGet<IssueComment[]>(
      token,
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${prNumber}/comments?per_page=100&page=${page}`,
    );
    if (!r.ok || !Array.isArray(r.data) || r.data.length === 0) break;
    all.push(...r.data);
    if (r.data.length < 100) break;
  }
  return all;
}

async function upsertIssueComment(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
  marker: string,
  body: string,
): Promise<{ ok: boolean; commentId?: number; message?: string }> {
  const comments = await listIssueComments(token, owner, repo, prNumber);
  const existingId = findExistingCommentId(comments, marker);

  if (existingId != null) {
    const r = await githubPatch<{ id?: number; message?: string }>(
      token,
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/comments/${existingId}`,
      { body },
    );
    if (!r.ok) {
      return {
        ok: false,
        message: r.data?.message || r.raw?.slice(0, 200),
      };
    }
    return { ok: true, commentId: r.data.id ?? existingId };
  }

  const r = await githubPost<{ id?: number; message?: string }>(
    token,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${prNumber}/comments`,
    { body },
  );
  if (!r.ok) {
    return { ok: false, message: r.data?.message || r.raw?.slice(0, 200) };
  }
  return { ok: true, commentId: r.data.id };
}

/**
 * Post (or update) a CodeRabbit-style PR summary comment for a completed
 * webhook-triggered scan. Safe to call always: silently skips when the scan
 * was not webhook-triggered, has no PR, has no connected GitHub repo, or no
 * OAuth token is available.
 */
export async function postScanPrSummary(scanId: string): Promise<void> {
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
          githubOwner: true,
          githubRepoName: true,
        },
      },
    },
  });

  if (!scan?.project) return;
  if (scan.sourceType !== "WEBHOOK") return;
  if (scan.prNumber == null) return;
  const { githubOwner, githubRepoName, organizationId, id: projectId } =
    scan.project;
  if (!githubOwner || !githubRepoName) {
    log.debug(
      { scanId },
      "PR summary skipped: project has no GitHub owner/repo",
    );
    return;
  }

  const token = await getOrgGithubAccessToken(organizationId);
  if (!token) {
    log.info(
      { scanId, organizationId },
      "PR summary skipped: no GitHub OAuth token for org",
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
      reviewUrl: buildReviewUrl(scan.id),
      status,
      errorMessage: scan.errorMessage,
    },
    marker,
  );

  const result = await upsertIssueComment(
    token,
    githubOwner,
    githubRepoName,
    scan.prNumber,
    marker,
    body,
  );

  if (!result.ok) {
    log.warn(
      { scanId, owner: githubOwner, repo: githubRepoName, msg: result.message },
      "Failed to upsert PR summary comment",
    );
  } else {
    log.info(
      {
        scanId,
        owner: githubOwner,
        repo: githubRepoName,
        prNumber: scan.prNumber,
        commentId: result.commentId,
      },
      "Posted PR security review summary",
    );
  }

  const reviewUrl = buildReviewUrl(scan.id);

  if (status === "COMPLETED" && scan.commitSha && topFindings.length > 0) {
    try {
      const inline = await postInlineReview({
        token,
        owner: githubOwner,
        repo: githubRepoName,
        prNumber: scan.prNumber,
        headSha: scan.commitSha,
        findings: topFindings,
        reviewUrl,
      });
      log.info(
        {
          scanId,
          prNumber: scan.prNumber,
          posted: inline.posted,
          skipped: inline.skipped,
        },
        "Inline review comments dispatched",
      );
    } catch (e) {
      log.warn({ scanId, e }, "Inline review failed (non-blocking)");
    }
  }

  if (scan.commitSha) {
    try {
      await postCommitStatus({
        token,
        owner: githubOwner,
        repo: githubRepoName,
        sha: scan.commitSha,
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
      log.warn({ scanId, e }, "Commit status post failed (non-blocking)");
    }
  }
}
