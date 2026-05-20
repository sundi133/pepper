import { prisma } from "./prisma";
import { getOrgBitbucketAuth } from "./bitbucket-connection";
import { bitbucketGet, bitbucketPost, bitbucketPut } from "./bitbucket-api";
import type { BitbucketAuth, BitbucketResponse } from "./bitbucket-api";
import { logger } from "./logger";
import {
  buildPrMarker,
  findExistingCommentId,
  renderPrSummary,
} from "./github-pr-summary";
import { postBitbucketInlineReview } from "./bitbucket-pr-inline";
import { postBitbucketCommitStatus } from "./bitbucket-pr-status";

const log = logger.child({ module: "bitbucket-pr-comment" });

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

interface BitbucketComment {
  id: number;
  content?: { raw?: string | null } | null;
  inline?: unknown;
}

interface BitbucketCommentList {
  values?: BitbucketComment[];
  next?: string | null;
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
 * List **general** PR comments (no `inline` field set). Bitbucket returns
 * both general and inline comments from the same endpoint; we filter to
 * the general ones because the summary lives at PR level, not on a line.
 */
async function listGeneralComments(
  auth: BitbucketAuth,
  workspace: string,
  repoSlug: string,
  prId: number,
): Promise<Array<{ id: number; body: string | null }>> {
  const out: Array<{ id: number; body: string | null }> = [];
  let path: string | null = `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/pullrequests/${prId}/comments?pagelen=100`;
  let pages = 0;
  while (path && pages < 10) {
    const r: BitbucketResponse<BitbucketCommentList> =
      await bitbucketGet<BitbucketCommentList>(auth, path);
    if (!r.ok || !r.data?.values) break;
    for (const c of r.data.values) {
      if (c.inline) continue; // skip inline; we only look for the summary
      out.push({ id: c.id, body: c.content?.raw ?? null });
    }
    const next = r.data.next;
    if (!next) break;
    const stripped = next.replace(/^https?:\/\/api\.bitbucket\.org\/2\.0/, "");
    path = stripped.startsWith("/") ? stripped : null;
    pages++;
  }
  return out;
}

async function upsertSummaryComment(
  auth: BitbucketAuth,
  workspace: string,
  repoSlug: string,
  prId: number,
  marker: string,
  body: string,
): Promise<{ ok: boolean; commentId?: number; message?: string }> {
  const existing = await listGeneralComments(auth, workspace, repoSlug, prId);
  // findExistingCommentId expects body keyed as `body`; adapt:
  const adapted = existing.map((c) => ({ id: c.id, body: c.body }));
  const existingId = findExistingCommentId(adapted, marker);

  if (existingId != null) {
    const r = await bitbucketPut<{ id?: number }>(
      auth,
      `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/pullrequests/${prId}/comments/${existingId}`,
      { content: { raw: body } },
    );
    if (!r.ok) {
      return {
        ok: false,
        message: r.raw?.slice(0, 200),
      };
    }
    return { ok: true, commentId: r.data.id ?? existingId };
  }

  const r = await bitbucketPost<{ id?: number }>(
    auth,
    `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/pullrequests/${prId}/comments`,
    { content: { raw: body } },
  );
  if (!r.ok) {
    return { ok: false, message: r.raw?.slice(0, 200) };
  }
  return { ok: true, commentId: r.data.id };
}

/**
 * Post (or update) the Pepper PR review on a Bitbucket Cloud PR for a
 * completed webhook-triggered scan. Mirrors `postScanPrSummary` on the
 * GitHub side. Safe to call always — silently skips when the scan was
 * not webhook-triggered, has no PR, no linked Bitbucket repo, or no app
 * password is connected for the org.
 */
export async function postScanBitbucketPrSummary(
  scanId: string,
): Promise<void> {
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
          bitbucketWorkspace: true,
          bitbucketRepoSlug: true,
        },
      },
    },
  });

  if (!scan?.project) return;
  if (scan.sourceType !== "WEBHOOK") return;
  if (scan.prNumber == null) return;
  const {
    bitbucketWorkspace,
    bitbucketRepoSlug,
    organizationId,
    id: projectId,
  } = scan.project;
  if (!bitbucketWorkspace || !bitbucketRepoSlug) {
    log.debug(
      { scanId },
      "Bitbucket PR summary skipped: project has no Bitbucket workspace/repo",
    );
    return;
  }

  const auth = await getOrgBitbucketAuth(organizationId);
  if (!auth) {
    log.info(
      { scanId, organizationId },
      "Bitbucket PR summary skipped: no Bitbucket app password for org",
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

  const result = await upsertSummaryComment(
    auth,
    bitbucketWorkspace,
    bitbucketRepoSlug,
    scan.prNumber,
    marker,
    body,
  );

  if (!result.ok) {
    log.warn(
      {
        scanId,
        workspace: bitbucketWorkspace,
        repo: bitbucketRepoSlug,
        msg: result.message,
      },
      "Failed to upsert Bitbucket PR summary comment",
    );
  } else {
    log.info(
      {
        scanId,
        workspace: bitbucketWorkspace,
        repo: bitbucketRepoSlug,
        prId: scan.prNumber,
        commentId: result.commentId,
      },
      "Posted Bitbucket PR security review summary",
    );
  }

  if (status === "COMPLETED" && scan.commitSha && topFindings.length > 0) {
    try {
      const inline = await postBitbucketInlineReview({
        auth,
        workspace: bitbucketWorkspace,
        repoSlug: bitbucketRepoSlug,
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
        "Bitbucket inline review comments dispatched",
      );
    } catch (e) {
      log.warn({ scanId, e }, "Bitbucket inline review failed (non-blocking)");
    }
  }

  if (scan.commitSha) {
    try {
      await postBitbucketCommitStatus({
        auth,
        workspace: bitbucketWorkspace,
        repoSlug: bitbucketRepoSlug,
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
      log.warn(
        { scanId, e },
        "Bitbucket commit status post failed (non-blocking)",
      );
    }
  }
}
