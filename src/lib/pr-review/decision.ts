/**
 * Whether a pull-request event gets a review (docs/PR_REVIEW_BOT_SPEC.md §3).
 * Pure: the webhook gathers the facts and acts on the answer.
 */
import { isTrustedAssociation } from "./commands";
import { matchesAny, type RepoConfig } from "./config";

export const REVIEW_ACTIONS = new Set(["opened", "reopened", "synchronize", "ready_for_review"]);

export interface PrFacts {
  action: string;
  draft: boolean;
  baseRef: string;
  author: { login: string; type?: string };
  authorAssociation: string | null;
  isFork: boolean;
  paused: boolean;
}

export type ReviewDecision =
  | { review: true; scan: "incremental" | "full" }
  | {
      review: false;
      reason: string;
      /** set when GitHub should show it on the commit */
      status?: string;
      /**
       * "pending" keeps a required check blocking (fork PRs nobody has
       * reviewed yet); "success" lets it pass (drafts, bots, paused…).
       */
      state?: "success" | "pending";
    };

const BOT_LOGIN = /\[bot\]$|^(dependabot|renovate|renovate-bot|github-actions|snyk-bot|greenkeeper)(\[bot\])?$/i;

export function decidePrReview(f: PrFacts, cfg: RepoConfig): ReviewDecision {
  if (!REVIEW_ACTIONS.has(f.action)) return { review: false, reason: `action ${f.action}` };
  if (!cfg.reviews.auto) return { review: false, reason: "automatic reviews are off", status: "Pepper: automatic review off (.pepper.yaml); comment @pepper review" };
  if (f.paused) return { review: false, reason: "paused", status: "Pepper: reviews paused on this PR (@pepper resume)" };
  if (f.draft && !cfg.reviews.drafts) return { review: false, reason: "draft", status: "Pepper: skipped, draft PR" };
  // Drafts were reviewed when opened; marking one ready doesn't change its code.
  if (f.action === "ready_for_review" && cfg.reviews.drafts) return { review: false, reason: "already reviewed as a draft" };
  if (!cfg.reviews.bots && (f.author.type === "Bot" || BOT_LOGIN.test(f.author.login))) {
    return { review: false, reason: "bot author", status: "Pepper: skipped, bot PR" };
  }
  if (!matchesAny(f.baseRef, cfg.reviews.base_branches)) {
    return { review: false, reason: `base branch ${f.baseRef}`, status: `Pepper: skipped, base branch ${f.baseRef}` };
  }
  if (f.isFork) {
    const forks = cfg.reviews.forks;
    if (forks === "none" || (forks === "collaborators" && !isTrustedAssociation(f.authorAssociation))) {
      return {
        review: false,
        reason: "fork PR from an outside contributor",
        status: "Pepper: waiting for a collaborator to comment @pepper review (fork PR)",
        state: "pending",
      };
    }
  }
  return { review: true, scan: cfg.reviews.scan };
}
