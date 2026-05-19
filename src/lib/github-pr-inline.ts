import { githubGet, githubPost } from "./github-api";
import { logger } from "./logger";
import {
  buildInlineCommentBody,
  extractFindingMarkers,
  parsePatchAddedLines,
  selectFindingsForInline,
  type InlineFinding,
} from "./github-pr-inline-format";

const log = logger.child({ module: "github-pr-inline" });

const MAX_INLINE_COMMENTS_PER_REVIEW = 30;

interface PrFile {
  filename: string;
  patch?: string | null;
  status?: string;
}

interface PrReviewComment {
  id: number;
  body?: string | null;
  user?: { type?: string; login?: string } | null;
}

async function fetchPrChangedFiles(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<Map<string, Set<number>>> {
  const out = new Map<string, Set<number>>();
  for (let page = 1; page <= 10; page++) {
    const r = await githubGet<PrFile[]>(
      token,
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/${prNumber}/files?per_page=100&page=${page}`,
    );
    if (!r.ok || !Array.isArray(r.data) || r.data.length === 0) break;
    for (const f of r.data) {
      if (!f.filename) continue;
      const lines = parsePatchAddedLines(f.patch ?? null);
      if (lines.size > 0) out.set(f.filename, lines);
    }
    if (r.data.length < 100) break;
  }
  return out;
}

async function fetchExistingReviewMarkers(
  token: string,
  owner: string,
  repo: string,
  prNumber: number,
): Promise<Set<string>> {
  const seen = new Set<string>();
  for (let page = 1; page <= 10; page++) {
    const r = await githubGet<PrReviewComment[]>(
      token,
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/${prNumber}/comments?per_page=100&page=${page}`,
    );
    if (!r.ok || !Array.isArray(r.data) || r.data.length === 0) break;
    for (const c of r.data) {
      for (const m of extractFindingMarkers(c.body)) seen.add(m);
    }
    if (r.data.length < 100) break;
  }
  return seen;
}

export interface PostInlineReviewInput {
  token: string;
  owner: string;
  repo: string;
  prNumber: number;
  headSha: string;
  findings: InlineFinding[];
  reviewUrl: string | null;
}

export async function postInlineReview(
  input: PostInlineReviewInput,
): Promise<{ posted: number; skipped: number }> {
  const { token, owner, repo, prNumber, headSha, findings, reviewUrl } = input;

  const [changedFileLines, existingMarkers] = await Promise.all([
    fetchPrChangedFiles(token, owner, repo, prNumber),
    fetchExistingReviewMarkers(token, owner, repo, prNumber),
  ]);

  if (changedFileLines.size === 0) {
    return { posted: 0, skipped: findings.length };
  }

  const picked = selectFindingsForInline(
    findings,
    changedFileLines,
    existingMarkers,
    MAX_INLINE_COMMENTS_PER_REVIEW,
  );

  if (picked.length === 0) {
    return { posted: 0, skipped: findings.length };
  }

  const indexByPosition = new Map<string, InlineFinding>();
  for (const f of findings) {
    if (!f.filePath || f.startLine == null) continue;
    indexByPosition.set(`${f.filePath}#${f.startLine}`, f);
  }

  const comments = picked.map((p) => {
    const finding = indexByPosition.get(`${p.path}#${p.line}`)!;
    return {
      path: p.path,
      line: p.line,
      side: p.side,
      body: buildInlineCommentBody(finding, { reviewUrl }),
    };
  });

  const r = await githubPost<{ id?: number; message?: string }>(
    token,
    `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/${prNumber}/reviews`,
    {
      commit_id: headSha,
      event: "COMMENT",
      body: `Pepper posted ${comments.length} inline security ${comments.length === 1 ? "comment" : "comments"} for new findings on this push.`,
      comments,
    },
  );

  if (!r.ok) {
    log.warn(
      { owner, repo, prNumber, status: r.status, msg: r.data?.message || r.raw?.slice(0, 200) },
      "Failed to create PR review with inline comments",
    );
    return { posted: 0, skipped: findings.length };
  }

  return {
    posted: comments.length,
    skipped: findings.length - comments.length,
  };
}
