import { NextRequest, NextResponse, after } from "next/server";
import { requireBitbucketWebhookAuth } from "@/lib/webhook-secrets";
import {
  findProjectForBitbucketWebhook,
  isBitbucketPushToDefaultBranch,
  mainBranchWebhookScanType,
  queueBitbucketWebhookScan,
} from "@/lib/bitbucket-webhook-scan";
import {
  ensureProjectForBitbucketRepo,
  handleBitbucketComment,
  handleBitbucketPullRequest,
  type BitbucketComment,
  type BitbucketPr,
  type BitbucketRepoPayload,
} from "@/lib/pr-review/bitbucket";
import { logger } from "@/lib/logger";

/**
 * Bitbucket Cloud webhooks.
 *
 * - `repo:push` — scan on push to the default branch (code changes)
 * - `pullrequest:created` / `pullrequest:updated` — PR reviews, through the
 *   shared review decision (docs/PR_REVIEW_PROVIDERS_SPEC.md §3.4)
 * - `pullrequest:comment_created` — `@pepper` commands (§3.5)
 *
 * A webhook authenticated with an organization's secret onboards repositories
 * it hasn't seen, so one workspace webhook covers them all (§3.3).
 *
 * Bitbucket signs the body with the webhook secret using HMAC SHA-256 and
 * puts the digest in `X-Hub-Signature` (format `sha256=<hex>`). If
 * `BITBUCKET_WEBHOOK_SECRET` is unset we skip verification (local dev).
 */
export async function POST(req: NextRequest) {
  const signature = req.headers.get("x-hub-signature");
  const eventKey = req.headers.get("x-event-key");
  const body = await req.text();

  const authResult = await requireBitbucketWebhookAuth(body, signature);
  if (!authResult.ok) {
    return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(body);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const repository = payload.repository as BitbucketRepoPayload | undefined;
  if (!repository?.full_name) {
    return NextResponse.json({ message: "Missing repository" });
  }

  const fullName = repository.full_name;
  const repoUrl = `https://bitbucket.org/${fullName}.git`;

  const lookup = {
    fullName,
    repoUuid: repository.uuid,
    organizationId: authResult.organizationId,
  };
  let project = await findProjectForBitbucketWebhook(lookup);
  // Onboard on PR and push events from an organization's own webhook (not on
  // comments, and never with the env-only secret, which names no organization).
  const isComment = eventKey === "pullrequest:comment_created";
  if (!project && authResult.organizationId && !isComment && eventKey?.match(/^(repo:push|pullrequest:(created|updated))$/)) {
    if (await ensureProjectForBitbucketRepo(authResult.organizationId, repository)) {
      project = await findProjectForBitbucketWebhook(lookup);
    }
  }
  if (!project) {
    return NextResponse.json({ message: "No matching project found" });
  }

  if (eventKey === "repo:push") {
    const push = payload.push as
      | {
          changes?: Array<{
            new?: {
              type?: string;
              name?: string;
              target?: { hash?: string };
            };
          }>;
        }
      | undefined;

    for (const change of push?.changes ?? []) {
      const branchName = change.new?.name;
      const commitSha = change.new?.target?.hash;
      if (change.new?.type !== "branch" || !branchName || !commitSha) {
        continue;
      }
      if (
        !isBitbucketPushToDefaultBranch({
          branchName,
          defaultBranch: project.defaultBranch,
        })
      ) {
        continue;
      }

      const result = await queueBitbucketWebhookScan({
        project,
        scanType: mainBranchWebhookScanType(),
        repoUrl,
        branch: project.defaultBranch,
        commitSha,
      });
      return NextResponse.json({
        scanId: result.scanId,
        status: result.status,
        trigger: "push_default_branch",
      });
    }

    return NextResponse.json({ message: "Event ignored" });
  }

  if (isComment) {
    const result = await handleBitbucketComment(
      project,
      fullName,
      payload as { comment?: BitbucketComment; pullrequest?: BitbucketPr; repository?: BitbucketRepoPayload },
      (work) =>
        after(async () => {
          try {
            await work();
          } catch (err) {
            logger.error({ err }, "Bitbucket PR command failed");
          }
        }),
    );
    return NextResponse.json(result);
  }

  if (
    eventKey !== "pullrequest:created" &&
    eventKey !== "pullrequest:updated"
  ) {
    return NextResponse.json({ message: "Event ignored" });
  }

  const pullRequest = payload.pullrequest as BitbucketPr | undefined;
  if (!pullRequest?.id) {
    return NextResponse.json({ message: "Missing pull request" });
  }

  return NextResponse.json(
    await handleBitbucketPullRequest(project, fullName, eventKey, pullRequest),
  );
}
