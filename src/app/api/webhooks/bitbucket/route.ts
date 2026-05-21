import { NextRequest, NextResponse } from "next/server";
import { requireBitbucketWebhookAuth } from "@/lib/webhook-secrets";
import {
  findProjectForBitbucketWebhook,
  isBitbucketPushToDefaultBranch,
  mainBranchWebhookScanType,
  queueBitbucketWebhookScan,
} from "@/lib/bitbucket-webhook-scan";

/**
 * Bitbucket Cloud webhooks.
 *
 * - `repo:push` — scan on push to the default branch (code changes)
 * - `pullrequest:created` / `pullrequest:updated` — incremental PR scans
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

  const repository = payload.repository as
    | { full_name?: string; uuid?: string }
    | undefined;
  if (!repository?.full_name) {
    return NextResponse.json({ message: "Missing repository" });
  }

  const fullName = repository.full_name;
  const repoUrl = `https://bitbucket.org/${fullName}.git`;

  const project = await findProjectForBitbucketWebhook({
    fullName,
    repoUuid: repository.uuid,
  });
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

  if (
    eventKey !== "pullrequest:created" &&
    eventKey !== "pullrequest:updated"
  ) {
    return NextResponse.json({ message: "Event ignored" });
  }

  const pullRequest = payload.pullrequest as
    | {
        id?: number;
        source?: {
          branch?: { name?: string };
          commit?: { hash?: string };
        };
        destination?: {
          commit?: { hash?: string };
        };
      }
    | undefined;

  if (!pullRequest?.id) {
    return NextResponse.json({ message: "Missing pull request" });
  }

  const branch = pullRequest.source?.branch?.name ?? null;
  const headSha = pullRequest.source?.commit?.hash ?? null;
  const baseSha = pullRequest.destination?.commit?.hash ?? null;
  const prId = pullRequest.id;

  const result = await queueBitbucketWebhookScan({
    project,
    scanType: "INCREMENTAL",
    repoUrl,
    branch: branch ?? project.defaultBranch,
    commitSha: headSha ?? undefined,
    baseSha: baseSha ?? undefined,
    prNumber: prId,
  });

  return NextResponse.json({
    scanId: result.scanId,
    status: result.status,
  });
}
