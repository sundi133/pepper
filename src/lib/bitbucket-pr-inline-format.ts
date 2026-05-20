/**
 * Pure helpers for posting inline review comments on Bitbucket Cloud PRs.
 *
 * Bitbucket's `/pullrequests/{id}/diff` endpoint returns one large unified
 * diff covering every changed file. This module splits it into per-file
 * patches and then reuses the same hunk parser that GitHub uses, since the
 * hunk grammar (`@@ -a,b +c,d @@`, ` `/`+`/`-` line sigils) is identical.
 */

import { parsePatchAddedLines } from "./github-pr-inline-format";

/**
 * Split a Bitbucket unified diff into a map of `new-file-path` → set of
 * line numbers on the new side that can receive an inline comment.
 */
export function parseBitbucketDiff(
  diffText: string | null | undefined,
): Map<string, Set<number>> {
  const out = new Map<string, Set<number>>();
  if (!diffText) return out;

  const lines = diffText.split("\n");
  let currentPath: string | null = null;
  let currentHunks: string[] = [];

  const flush = () => {
    if (currentPath && currentHunks.length > 0) {
      const lineSet = parsePatchAddedLines(currentHunks.join("\n"));
      if (lineSet.size > 0) {
        out.set(currentPath, lineSet);
      }
    }
    currentPath = null;
    currentHunks = [];
  };

  for (const raw of lines) {
    if (raw.startsWith("diff --git ")) {
      flush();
      // diff --git a/path/to/file b/path/to/file
      const m = raw.match(/^diff --git a\/(.*?) b\/(.*?)$/);
      currentPath = m ? m[2] : null;
      continue;
    }

    if (currentPath == null) continue;

    if (
      raw.startsWith("index ") ||
      raw.startsWith("--- ") ||
      raw.startsWith("+++ ") ||
      raw.startsWith("new file mode") ||
      raw.startsWith("deleted file mode") ||
      raw.startsWith("similarity index") ||
      raw.startsWith("rename from") ||
      raw.startsWith("rename to") ||
      raw.startsWith("Binary files")
    ) {
      continue;
    }

    // Inside (or about to be inside) a hunk — collect the line for the
    // shared parser. Hunk-header detection lives there.
    currentHunks.push(raw);
  }
  flush();

  return out;
}

/**
 * Re-export GitHub helpers so the Bitbucket modules don't import directly
 * from a `github-*` file (cosmetic, but easier to refactor later).
 */
export {
  buildFindingMarker,
  extractFindingMarkers,
  buildInlineCommentBody,
  selectFindingsForInline,
  type InlineFinding,
} from "./github-pr-inline-format";
