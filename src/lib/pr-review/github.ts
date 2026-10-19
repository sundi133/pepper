/** GitHub calls the PR bot makes: read a PR, comment, react, load `.pepper.yaml`. */
import { getFileOnRef, githubGet, githubPost } from "@/lib/github-api";
import { CONFIG_FILE_NAMES, parseRepoConfig, type RepoConfig } from "./config";

const repoPath = (owner: string, repo: string) => `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;

export interface PullRequestInfo {
  number: number;
  draft?: boolean;
  state?: string;
  user?: { login: string; type?: string };
  author_association?: string;
  head: { ref: string; sha: string; repo: { full_name: string } | null };
  base: { ref: string; sha: string; repo: { full_name: string } };
}

export async function getPullRequest(token: string, owner: string, repo: string, n: number): Promise<PullRequestInfo | null> {
  const r = await githubGet<PullRequestInfo>(token, `${repoPath(owner, repo)}/pulls/${n}`);
  return r.ok ? r.data : null;
}

export function postIssueComment(token: string, owner: string, repo: string, n: number, body: string) {
  return githubPost(token, `${repoPath(owner, repo)}/issues/${n}/comments`, { body });
}

export function replyToReviewComment(token: string, owner: string, repo: string, n: number, commentId: number, body: string) {
  return githubPost(token, `${repoPath(owner, repo)}/pulls/${n}/comments/${commentId}/replies`, { body });
}

export function addReaction(token: string, owner: string, repo: string, kind: "issue" | "review", commentId: number, content: "eyes" | "+1" | "confused") {
  const path = kind === "issue" ? `issues/comments/${commentId}/reactions` : `pulls/comments/${commentId}/reactions`;
  return githubPost(token, `${repoPath(owner, repo)}/${path}`, { content });
}

export async function getReviewComment(token: string, owner: string, repo: string, commentId: number): Promise<{ id: number; body: string } | null> {
  const r = await githubGet<{ id: number; body: string }>(token, `${repoPath(owner, repo)}/pulls/comments/${commentId}`);
  return r.ok ? r.data : null;
}

/** `.pepper.yaml` at `ref` (first of the accepted names), parsed; defaults when absent. */
export async function loadRepoConfig(token: string, owner: string, repo: string, ref: string): Promise<{ config: RepoConfig; error: string | null; found: boolean }> {
  for (const name of CONFIG_FILE_NAMES) {
    const f = await getFileOnRef(token, owner, repo, name, ref);
    if (f.ok && typeof f.content === "string") return { ...parseRepoConfig(f.content), found: true };
    if (f.status !== 404) break; // an error other than "not there": use the defaults
  }
  return { ...parseRepoConfig(null), found: false };
}
