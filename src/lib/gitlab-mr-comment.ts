import { prisma } from "./prisma";
import { getOrgGitLabAuth } from "./gitlab-connection";
import { gitlabGet, gitlabPost, gitlabPut } from "./gitlab-api";
import type { GitLabAuth } from "./gitlab-api";
import { logger } from "./logger";
import { buildPrMarker, findExistingCommentId, renderPrSummary } from "./github-pr-summary";
import {
  parsePatchAddedLines,
  buildInlineCommentBody,
  extractFindingMarkers,
  selectFindingsForInline,
  type InlineFinding,
} from "./github-pr-inline-format";

const log = logger.child({ module: "gitlab-mr-comment" });

const MAX_INLINE_PER_MR = 30;

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function buildReviewUrl(scanId: string): string | null {
  const base =
    process.env.NEXTAUTH_URL ||
    process.env.APP_URL ||
    process.env.NEXT_PUBLIC_APP_URL;
  if (!base) return null;
  return `${base.replace(/\/+$/, "")}/scans/${scanId}`;
}

// ─── GitLab MR interfaces ─────────────────────────────────────────────────────

interface GitLabMrDiffRefs {
  base_sha: string;
  head_sha: string;
  start_sha: string;
}

interface GitLabMr {
  iid: number;
  diff_refs?: GitLabMrDiffRefs | null;
  sha?: string | null;
}

interface GitLabNote {
  id: number;
  body?: string | null;
  system?: boolean;
  author?: { bot?: boolean };
}

interface GitLabDiffChange {
  old_path: string;
  new_path: string;
  diff?: string | null;
  new_file?: boolean;
  deleted_file?: boolean;
  renamed_file?: boolean;
}

interface GitLabMrChanges {
  changes?: GitLabDiffChange[];
}

// ─── Summary note (PR-level) ──────────────────────────────────────────────────

async function listMrNotes(
  auth: GitLabAuth,
  projectId: number,
  mrIid: number,
): Promise<GitLabNote[]> {
  const all: GitLabNote[] = [];
  for (let page = 1; page <= 10; page++) {
    const r = await gitlabGet<GitLabNote[]>(
      auth,
      `/projects/${projectId}/merge_requests/${mrIid}/notes?system=false&per_page=100&page=${page}`,
    );
    if (!r.ok || !Array.isArray(r.data) || r.data.length === 0) break;
    all.push(...r.data);
    if (r.data.length < 100) break;
  }
  return all;
}

async function upsertMrNote(
  auth: GitLabAuth,
  projectId: number,
  mrIid: number,
  marker: string,
  body: string,
): Promise<{ ok: boolean; noteId?: number }> {
  const notes = await listMrNotes(auth, projectId, mrIid);
  const existingId = findExistingCommentId(
    notes.map((n) => ({ id: n.id, body: n.body ?? "" })),
    marker,
  );

  if (existingId != null) {
    const r = await gitlabPut<{ id?: number }>(
      auth,
      `/projects/${projectId}/merge_requests/${mrIid}/notes/${existingId}`,
      { body },
    );
    return { ok: r.ok, noteId: r.data.id ?? existingId };
  }

  const r = await gitlabPost<{ id?: number }>(
    auth,
    `/projects/${projectId}/merge_requests/${mrIid}/notes`,
    { body },
  );
  return { ok: r.ok, noteId: r.data.id };
}

// ─── Inline diff discussions ──────────────────────────────────────────────────

async function fetchMr(
  auth: GitLabAuth,
  projectId: number,
  mrIid: number,
): Promise<GitLabMr | null> {
  const r = await gitlabGet<GitLabMr>(
    auth,
    `/projects/${projectId}/merge_requests/${mrIid}`,
  );
  if (!r.ok) return null;
  return r.data;
}

async function fetchMrChangedFiles(
  auth: GitLabAuth,
  projectId: number,
  mrIid: number,
): Promise<Map<string, Set<number>>> {
  const r = await gitlabGet<GitLabMrChanges>(
    auth,
    `/projects/${projectId}/merge_requests/${mrIid}/changes`,
  );
  if (!r.ok || !Array.isArray(r.data?.changes)) return new Map();

  const out = new Map<string, Set<number>>();
  for (const change of r.data.changes) {
    if (change.deleted_file) continue;
    const path = change.new_path || change.old_path;
    const lines = parsePatchAddedLines(change.diff ?? null);
    if (lines.size > 0) out.set(path, lines);
  }
  return out;
}

async function fetchExistingInlineMarkers(
  auth: GitLabAuth,
  projectId: number,
  mrIid: number,
): Promise<Set<string>> {
  const seen = new Set<string>();
  // Fetch all discussion notes (includes inline ones)
  for (let page = 1; page <= 10; page++) {
    const r = await gitlabGet<Array<{ notes?: GitLabNote[] }>>(
      auth,
      `/projects/${projectId}/merge_requests/${mrIid}/discussions?per_page=100&page=${page}`,
    );
    if (!r.ok || !Array.isArray(r.data) || r.data.length === 0) break;
    for (const disc of r.data) {
      for (const note of disc.notes ?? []) {
        for (const m of extractFindingMarkers(note.body)) seen.add(m);
      }
    }
    if (r.data.length < 100) break;
  }
  return seen;
}

async function postInlineDiscussions(
  auth: GitLabAuth,
  projectId: number,
  mrIid: number,
  diffRefs: GitLabMrDiffRefs,
  findings: InlineFinding[],
  changedFileLines: Map<string, Set<number>>,
  existingMarkers: Set<string>,
  reviewUrl: string | null,
): Promise<{ posted: number; skipped: number }> {
  const picked = selectFindingsForInline(
    findings,
    changedFileLines,
    existingMarkers,
    MAX_INLINE_PER_MR,
  );

  if (picked.length === 0) return { posted: 0, skipped: findings.length };

  const indexByPosition = new Map<string, InlineFinding>();
  for (const f of findings) {
    if (!f.filePath || f.startLine == null) continue;
    indexByPosition.set(`${f.filePath}#${f.startLine}`, f);
  }

  let posted = 0;
  for (const p of picked) {
    const finding = indexByPosition.get(`${p.path}#${p.line}`)!;
    const body = buildInlineCommentBody(finding, { reviewUrl });

    const r = await gitlabPost<{ id?: string }>(
      auth,
      `/projects/${projectId}/merge_requests/${mrIid}/discussions`,
      {
        body,
        position: {
          position_type: "text",
          base_sha: diffRefs.base_sha,
          start_sha: diffRefs.start_sha,
          head_sha: diffRefs.head_sha,
          new_path: p.path,
          new_line: p.line,
        },
      },
    );

    if (r.ok) {
      posted++;
    } else {
      log.warn(
        { projectId, mrIid, path: p.path, line: p.line, status: r.status },
        "Failed to post GitLab inline discussion",
      );
    }
  }

  return { posted, skipped: findings.length - posted };
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/**
 * Post (or update) a summary MR note and inline diff comments for a completed
 * webhook-triggered scan on GitLab. Safe to call always — silently no-ops when
 * the scan is not webhook-triggered, has no PR, or no GitLab token is stored.
 */
export async function postScanGitLabMrSummary(scanId: string): Promise<void> {
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
          gitlabProjectId: true,
          gitlabNamespace: true,
        },
      },
    },
  });

  if (!scan?.project) return;
  if (scan.sourceType !== "WEBHOOK") return;
  if (scan.prNumber == null) return;

  const { gitlabProjectId, organizationId } = scan.project;
  if (!gitlabProjectId) {
    log.debug({ scanId }, "GitLab MR note skipped: project has no gitlabProjectId");
    return;
  }

  const auth = await getOrgGitLabAuth(organizationId);
  if (!auth) {
    log.info({ scanId, organizationId }, "GitLab MR note skipped: no GitLab token for org");
    return;
  }

  const status: "COMPLETED" | "FAILED" =
    scan.status === "COMPLETED" ? "COMPLETED" : "FAILED";

  const topFindings =
    status === "COMPLETED"
      ? await prisma.finding.findMany({
          where: { scanId, status: "OPEN", scan: { project: { organizationId } } },
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
    (a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99),
  );

  const marker = buildPrMarker(scan.project.id);
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

  const noteResult = await upsertMrNote(
    auth,
    gitlabProjectId,
    scan.prNumber,
    marker,
    body,
  );

  if (!noteResult.ok) {
    log.warn(
      { scanId, gitlabProjectId, mrIid: scan.prNumber },
      "Failed to upsert GitLab MR summary note",
    );
  } else {
    log.info(
      { scanId, gitlabProjectId, mrIid: scan.prNumber, noteId: noteResult.noteId },
      "Posted GitLab MR security review summary",
    );
  }

  // Inline diff comments
  if (status === "COMPLETED" && topFindings.length > 0) {
    try {
      const mr = await fetchMr(auth, gitlabProjectId, scan.prNumber);
      if (!mr?.diff_refs) {
        log.debug({ scanId }, "GitLab inline skipped: no diff_refs on MR");
        return;
      }

      const [changedFileLines, existingMarkers] = await Promise.all([
        fetchMrChangedFiles(auth, gitlabProjectId, scan.prNumber),
        fetchExistingInlineMarkers(auth, gitlabProjectId, scan.prNumber),
      ]);

      const inline = await postInlineDiscussions(
        auth,
        gitlabProjectId,
        scan.prNumber,
        mr.diff_refs,
        topFindings,
        changedFileLines,
        existingMarkers,
        reviewUrl,
      );

      log.info(
        { scanId, mrIid: scan.prNumber, posted: inline.posted, skipped: inline.skipped },
        "GitLab inline diff comments dispatched",
      );
    } catch (e) {
      log.warn({ scanId, e }, "GitLab inline review failed (non-blocking)");
    }
  }
}
