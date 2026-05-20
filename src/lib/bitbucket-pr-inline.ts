import { bitbucketGet, bitbucketGetText, bitbucketPost } from "./bitbucket-api";
import type { BitbucketAuth, BitbucketResponse } from "./bitbucket-api";
import { logger } from "./logger";
import {
  buildInlineCommentBody,
  extractFindingMarkers,
  parseBitbucketDiff,
  selectFindingsForInline,
  type InlineFinding,
} from "./bitbucket-pr-inline-format";

const log = logger.child({ module: "bitbucket-pr-inline" });

const MAX_INLINE_COMMENTS_PER_REVIEW = 30;

interface BitbucketComment {
  id: number;
  content?: { raw?: string | null } | null;
  inline?: { path?: string; to?: number | null; from?: number | null } | null;
}

interface BitbucketCommentList {
  values?: BitbucketComment[];
  next?: string | null;
}

async function fetchPrChangedFiles(
  auth: BitbucketAuth,
  workspace: string,
  repoSlug: string,
  prId: number,
): Promise<Map<string, Set<number>>> {
  const r = await bitbucketGetText(
    auth,
    `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/pullrequests/${prId}/diff`,
  );
  if (!r.ok) {
    log.warn(
      { workspace, repoSlug, prId, status: r.status },
      "Failed to fetch PR diff",
    );
    return new Map();
  }
  return parseBitbucketDiff(r.text);
}

async function fetchExistingReviewMarkers(
  auth: BitbucketAuth,
  workspace: string,
  repoSlug: string,
  prId: number,
): Promise<Set<string>> {
  const seen = new Set<string>();
  let path: string | null = `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/pullrequests/${prId}/comments?pagelen=100`;
  let pages = 0;
  while (path && pages < 10) {
    const r: BitbucketResponse<BitbucketCommentList> =
      await bitbucketGet<BitbucketCommentList>(auth, path);
    if (!r.ok || !r.data?.values) break;
    for (const c of r.data.values) {
      for (const m of extractFindingMarkers(c.content?.raw ?? null)) {
        seen.add(m);
      }
    }
    const next = r.data.next;
    if (!next) break;
    // `next` is a fully qualified URL — strip the base to keep our helper happy.
    const stripped = next.replace(/^https?:\/\/api\.bitbucket\.org\/2\.0/, "");
    path = stripped.startsWith("/") ? stripped : null;
    pages++;
  }
  return seen;
}

export interface PostBitbucketInlineReviewInput {
  auth: BitbucketAuth;
  workspace: string;
  repoSlug: string;
  prId: number;
  findings: InlineFinding[];
  reviewUrl: string | null;
}

export async function postBitbucketInlineReview(
  input: PostBitbucketInlineReviewInput,
): Promise<{ posted: number; skipped: number }> {
  const { auth, workspace, repoSlug, prId, findings, reviewUrl } = input;

  const [changedFileLines, existingMarkers] = await Promise.all([
    fetchPrChangedFiles(auth, workspace, repoSlug, prId),
    fetchExistingReviewMarkers(auth, workspace, repoSlug, prId),
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

  let posted = 0;
  for (const p of picked) {
    const finding = indexByPosition.get(`${p.path}#${p.line}`)!;
    const body = buildInlineCommentBody(finding, { reviewUrl });
    const r = await bitbucketPost(
      auth,
      `/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(repoSlug)}/pullrequests/${prId}/comments`,
      {
        content: { raw: body },
        inline: { path: p.path, to: p.line },
      },
    );
    if (r.ok) {
      posted++;
    } else {
      log.warn(
        {
          workspace,
          repoSlug,
          prId,
          path: p.path,
          line: p.line,
          status: r.status,
        },
        "Failed to post Bitbucket inline comment",
      );
    }
  }

  return { posted, skipped: findings.length - posted };
}
