/**
 * Pure helpers for posting Azure DevOps Services PR inline review threads.
 *
 * ADO models inline review as **threads** on a pull request. A thread has
 * a `threadContext` with `filePath` and a line/offset range on either the
 * left (`leftFileStart`/`leftFileEnd`) or right (`rightFileStart`/
 * `rightFileEnd`) side. Comments are children of the thread. We always
 * anchor on the right side (new file content).
 *
 * Unlike GitHub/Bitbucket, ADO accepts inline comments on any line in the
 * file — they don't have to be inside the diff hunks. We still filter
 * findings to only those whose file changed in the PR, to avoid spamming
 * unchanged code with new findings.
 *
 * Marker helpers and `InlineFinding` are re-exported from the GitHub
 * helpers so the dedup string and body template stay identical across
 * providers.
 */

/**
 * ADO iteration `changes` response shape (trimmed to what we use).
 */
export interface AzureIterationChange {
  item?: {
    path?: string;
    isFolder?: boolean;
  };
  changeType?: string;
}

export interface AzureIterationChangesResponse {
  changeEntries?: AzureIterationChange[];
}

/**
 * Build the set of file paths whose content changed in the iteration's
 * `changes` response. ADO returns paths with a leading `/`; we normalise
 * to repo-relative (no leading slash) so the comparison against finding
 * `filePath` values is uniform.
 *
 * `delete`-only changes are excluded since there's no right-side line to
 * comment on.
 */
export function parseAzureChangedFiles(
  response: AzureIterationChangesResponse | null | undefined,
): Set<string> {
  const out = new Set<string>();
  if (!response?.changeEntries) return out;
  for (const c of response.changeEntries) {
    const path = c.item?.path;
    if (!path) continue;
    if (c.item?.isFolder) continue;
    const ct = (c.changeType ?? "").toLowerCase();
    if (ct && ct.split(",").every((t) => t.trim() === "delete")) continue;
    out.add(path.startsWith("/") ? path.slice(1) : path);
  }
  return out;
}

export {
  buildFindingMarker,
  extractFindingMarkers,
  buildInlineCommentBody,
  type InlineFinding,
} from "./github-pr-inline-format";
