import {
  OPEN_FIX_PR_CONFIRM_MESSAGE,
  postOpenFixPr,
  type PostOpenFixPrResult,
} from "@/lib/open-fix-pr-client";

export type GithubConnectionCheck = {
  connected: boolean;
};

export async function fetchGithubConnected(): Promise<boolean> {
  try {
    const res = await fetch("/api/integrations/github");
    if (!res.ok) return false;
    const data = (await res.json()) as GithubConnectionCheck;
    return Boolean(data.connected);
  } catch {
    return false;
  }
}

/** Relative path for OAuth return (current page + openPr query). */
export function buildOpenFixPrReturnPath(scanId: string, findingId: string): string {
  const params = new URLSearchParams();
  params.set("openPr", findingId);
  return `/scans/${scanId}?${params.toString()}`;
}

export function redirectToGithubOAuth(returnTo: string): void {
  const url = `/api/integrations/github/connect?returnTo=${encodeURIComponent(returnTo)}`;
  window.location.href = url;
}

/**
 * Open fix PR: confirm → OAuth if needed → create PR with AI fix.
 * Redirects away when GitHub is not connected.
 */
export async function runOpenFixPrFlow(
  scanId: string,
  findingId: string,
  options?: {
    skipConfirm?: boolean;
    repoUrl?: string;
    branch?: string;
  },
): Promise<PostOpenFixPrResult | { redirected: true }> {
  if (
    !options?.skipConfirm &&
    !window.confirm(OPEN_FIX_PR_CONFIRM_MESSAGE)
  ) {
    return { ok: false, status: 0, error: "Cancelled", code: "CANCELLED" };
  }

  const connected = await fetchGithubConnected();
  if (!connected) {
    redirectToGithubOAuth(buildOpenFixPrReturnPath(scanId, findingId));
    return { redirected: true };
  }

  const result = await postOpenFixPr(scanId, findingId, {
    repoUrl: options?.repoUrl,
    branch: options?.branch,
  });
  if (!result.ok && result.code === "GITHUB_OAUTH_REQUIRED") {
    redirectToGithubOAuth(buildOpenFixPrReturnPath(scanId, findingId));
    return { redirected: true };
  }
  return result;
}
