import { NextRequest, NextResponse } from "next/server";
import { requireGithubWebhookAuth } from "@/lib/webhook-secrets";
import {
  findProjectForGithubWebhook,
  isMergedPullRequestToDefaultBranch,
  isPushToDefaultBranch,
  mainBranchWebhookScanType,
  queueGithubWebhookScan,
} from "@/lib/github-webhook-scan";

export async function POST(req: NextRequest) {
  const signature = req.headers.get("x-hub-signature-256");
  const event = req.headers.get("x-github-event");
  const body = await req.text();

  const authResult = await requireGithubWebhookAuth(body, signature);
  if (!authResult.ok) {
    return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
  }

  const payload = JSON.parse(body) as Record<string, unknown>;
  const fullName = (payload.repository as { full_name?: string } | undefined)
    ?.full_name;
  const cloneUrl = (payload.repository as { clone_url?: string } | undefined)
    ?.clone_url;

  if (!fullName || !cloneUrl) {
    return NextResponse.json({ message: "Event ignored" });
  }

  const project = await findProjectForGithubWebhook(fullName);
  if (!project) {
    return NextResponse.json({ message: "No matching project found" });
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

    if (action && ["opened", "synchronize"].includes(action) && pr) {
      const result = await queueGithubWebhookScan({
        project,
        scanType: "INCREMENTAL",
        repoUrl: cloneUrl,
        branch: pr.head?.ref ?? project.defaultBranch,
        commitSha: pr.head?.sha,
        baseSha: pr.base?.sha,
        prNumber: pr.number,
      });
      return NextResponse.json({
        scanId: result.scanId,
        status: result.status,
      });
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
