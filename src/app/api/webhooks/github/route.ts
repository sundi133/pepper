import { NextRequest, NextResponse, after } from "next/server";
import { requireGithubWebhookAuth } from "@/lib/webhook-secrets";
import {
  findProjectForGithubWebhook,
  isMergedPullRequestToDefaultBranch,
  isPushToDefaultBranch,
  mainBranchWebhookScanType,
  queueGithubWebhookScan,
} from "@/lib/github-webhook-scan";
import { authenticateAppWebhook } from "@/lib/github-app-webhook";
import { ensureProjectForGithubRepo, type RepoPayload } from "@/lib/pr-review/onboard";
import { handlePrComment, handlePullRequestReview } from "@/lib/pr-review/handle";
import { REVIEW_ACTIONS } from "@/lib/pr-review/decision";
import { logger } from "@/lib/logger";

export async function POST(req: NextRequest) {
  const signature = req.headers.get("x-hub-signature-256");
  const event = req.headers.get("x-github-event");
  const body = await req.text();

  // Deliveries from the GitHub App are signed with its own secret; the linked
  // installation decides the organization (docs/GITHUB_APP_SPEC.md §8).
  // Everything else uses the per-organization webhook secrets as before.
  const app = await authenticateAppWebhook({
    body,
    signature,
    event,
    secret: process.env.GITHUB_APP_WEBHOOK_SECRET?.trim(),
  });
  if (app.kind === "handled") {
    return NextResponse.json({ message: app.message });
  }
  const authResult =
    app.kind === "event"
      ? ({ ok: true, organizationId: app.organizationId } as const)
      : await requireGithubWebhookAuth(body, signature);
  if (!authResult.ok) {
    return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
  }

  const payload = JSON.parse(body) as Record<string, unknown>;
  const fullName = (payload.repository as { full_name?: string } | undefined)
    ?.full_name;

  if (!fullName) {
    return NextResponse.json({ message: "Event ignored" });
  }

  let project = await findProjectForGithubWebhook(
    fullName,
    authResult.organizationId,
  );
  // Zero-setup onboarding: a repository the App was installed on gets its
  // project on its first pull request or push (docs/PR_REVIEW_BOT_SPEC.md §2).
  if (!project && app.kind === "event" && (event === "pull_request" || event === "push")) {
    const created = await ensureProjectForGithubRepo(app.organizationId, payload.repository as RepoPayload);
    if (created) project = await findProjectForGithubWebhook(fullName, app.organizationId);
  }
  if (!project) {
    return NextResponse.json({ message: "No matching project found" });
  }

  // `@pepper` commands in PR comments (docs/PR_REVIEW_BOT_SPEC.md §4). Slow
  // work (scans, fix PRs) runs after the response, within GitHub's timeout.
  if (event === "issue_comment" || event === "pull_request_review_comment") {
    const result = await handlePrComment(project, event, payload as never, (work) =>
      after(async () => {
        try {
          await work();
        } catch (err) {
          logger.error({ err, event }, "PR command failed");
        }
      }),
    );
    return NextResponse.json(result);
  }

  // Always clone from the project's own stored, trusted repoUrl — never the
  // webhook payload's clone_url, which is attacker-controlled and would
  // otherwise let a forged/replayed webhook redirect the org's credentialed
  // clone to an arbitrary host.
  const cloneUrl = project.repoUrl;
  if (!cloneUrl) {
    return NextResponse.json({ message: "Project has no repo URL configured" });
  }

  // PR opened / updated — incremental scan on head branch
  if (event === "pull_request") {
    const action = payload.action as string | undefined;
    const pr = payload.pull_request as
      | {
          head?: { ref?: string; sha?: string };
          base?: { ref?: string; sha?: string };
          number?: number;
          merged?: boolean;
          merge_commit_sha?: string | null;
        }
      | undefined;

    // opened, reopened, synchronize, ready_for_review: review unless the
    // repository's settings, a pause, a draft or a bot author say otherwise
    // (docs/PR_REVIEW_BOT_SPEC.md §3).
    if (action && REVIEW_ACTIONS.has(action) && pr) {
      const result = await handlePullRequestReview(project, payload as never);
      return NextResponse.json(result);
    }

    // PR merged into default branch — re-run SAST on main
    if (
      action === "closed" &&
      pr &&
      isMergedPullRequestToDefaultBranch({
        merged: Boolean(pr.merged),
        baseRef: pr.base?.ref ?? "main",
        defaultBranch: project.defaultBranch,
      })
    ) {
      const mergeSha = pr.merge_commit_sha?.trim();
      if (!mergeSha) {
        return NextResponse.json({ message: "Merge commit missing" });
      }
      const result = await queueGithubWebhookScan({
        project,
        scanType: mainBranchWebhookScanType(),
        repoUrl: cloneUrl,
        branch: pr.base?.ref ?? project.defaultBranch,
        commitSha: mergeSha,
      });
      return NextResponse.json({
        scanId: result.scanId,
        status: result.status,
        trigger: "pr_merged",
      });
    }

    return NextResponse.json({ message: "Event ignored" });
  }

  // Direct push to default branch (includes merge commits)
  if (event === "push") {
    const ref = payload.ref as string | undefined;
    const after = payload.after as string | undefined;
    if (!ref || !after || /^0+$/.test(after)) {
      return NextResponse.json({ message: "Event ignored" });
    }
    if (
      !isPushToDefaultBranch({
        ref,
        defaultBranch: project.defaultBranch,
      })
    ) {
      return NextResponse.json({ message: "Event ignored" });
    }

    const result = await queueGithubWebhookScan({
      project,
      scanType: mainBranchWebhookScanType(),
      repoUrl: cloneUrl,
      branch: project.defaultBranch,
      commitSha: after,
    });
    return NextResponse.json({
      scanId: result.scanId,
      status: result.status,
      trigger: "push_default_branch",
    });
  }

  return NextResponse.json({ message: "Event ignored" });
}
