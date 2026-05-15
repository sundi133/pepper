import {
  parseGithubRepo,
  resolveGithubRepoUrlForOpenPr,
} from "@/lib/github-source-link";

/** Shown in the browser before calling the open-PR API. */
export const OPEN_FIX_PR_CONFIRM_MESSAGE =
  "Create a new GitHub branch and open a pull request? Pepper fetches the current file from GitHub (not necessarily identical to an upload/SVN scan tree), uses your LLM to rewrite that file, then pushes one commit. Always review the diff before merging.";

/** Scan/repo context for GitHub line links and opening a fix PR (from scan detail). */
export type FixPrScanSourceContext = {
  scanId: string;
  sourceType: string;
  repoUrl: string | null;
  scanSourceRef?: string | null;
  defaultBranch?: string;
  branch?: string | null;
  commitSha?: string | null;
};

export function resolveGithubRepoForFixPr(
  ctx: FixPrScanSourceContext | undefined,
): ReturnType<typeof parseGithubRepo> {
  if (!ctx) return null;
  const repoUrl = resolveGithubRepoUrlForOpenPr({
    projectRepoUrl: ctx.repoUrl,
    scanSourceType: ctx.sourceType,
    scanSourceRef: ctx.scanSourceRef,
  });
  return parseGithubRepo(repoUrl);
}

export function canOpenFixPr(
  ctx: FixPrScanSourceContext | undefined,
  filePath: string | null | undefined,
): boolean {
  return Boolean(
    ctx?.scanId?.trim() && filePath?.trim() && resolveGithubRepoForFixPr(ctx),
  );
}

export function fixPrUnavailableReason(
  ctx: FixPrScanSourceContext | undefined,
  filePath: string | null | undefined,
): string | null {
  if (!ctx?.scanId?.trim()) return "Missing scan context.";
  if (!filePath?.trim()) {
    return "This finding has no file path; open the detail view after the scanner reports a location.";
  }
  if (!resolveGithubRepoForFixPr(ctx)) {
    return "No GitHub repository for this scan. Set the project repository URL to a github.com clone link, or run the scan from a GitHub clone / webhook.";
  }
  return null;
}

export type PostOpenFixPrResult =
  | { ok: true; pullRequestUrl: string }
  | {
      ok: false;
      error: string;
      status: number;
      code?: string;
    };

export async function postOpenFixPr(
  scanId: string,
  findingId: string,
  options?: { repoUrl?: string; branch?: string },
): Promise<PostOpenFixPrResult> {
  const res = await fetch(
    `/api/scans/${scanId}/findings/${findingId}/open-pr`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repoUrl: options?.repoUrl?.trim() || undefined,
        branch: options?.branch?.trim() || undefined,
      }),
    },
  );
  const raw = await res.text();
  let j: { pullRequestUrl?: string; error?: string; code?: string } = {};
  if (raw) {
    try {
      j = JSON.parse(raw) as typeof j;
    } catch {
      return {
        ok: false,
        status: res.status || 500,
        error: res.ok
          ? "Unexpected response from server"
          : `Request failed (${res.status})`,
      };
    }
  }
  if (!res.ok) {
    return {
      ok: false,
      status: res.status,
      error: j.error || `Failed to open pull request (${res.status})`,
      code: j.code,
    };
  }
  if (!j.pullRequestUrl) {
    return {
      ok: false,
      status: 500,
      error: "Pull request created but no URL was returned",
    };
  }
  return { ok: true, pullRequestUrl: j.pullRequestUrl };
}
