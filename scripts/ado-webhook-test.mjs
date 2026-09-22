#!/usr/bin/env node
/**
 * Azure DevOps webhook loop tester.
 *
 * Fires a realistic Azure DevOps service-hook payload (git.push or
 * git.pullrequest.updated) at a running Pepper instance so you can validate the
 * full end-to-end path without a real IdP/ADO server:
 *
 *   webhook  →  Basic-auth check  →  project lookup by azureRepoId  →  scan queued
 *
 * The response tells you the scanId and whether a scan was queued. Follow the
 * scan in Pepper to see findings, the build gate, and (for a PR event) the
 * status check + inline comments posted back to ADO.
 *
 * Works for both Azure DevOps Services (cloud) and Azure DevOps Server (on-prem)
 * — the webhook payload shape is identical; only the repository.id must match a
 * connected Pepper project.
 *
 * Usage:
 *   node scripts/ado-webhook-test.mjs --repo-id <ADO_REPO_GUID> [options]
 *
 * Options:
 *   --url <base>       Pepper base URL         (default: http://localhost:3000)
 *   --secret <value>   Webhook Basic-auth password
 *                        (or env AZURE_DEVOPS_WEBHOOK_SECRET)
 *   --repo-id <guid>   ADO repository id of a connected project   (required)
 *   --event push|pr    Which event to send                       (default: push)
 *   --branch <name>    Branch for a push event          (default: main)
 *   --commit <sha>     Commit id             (default: random 40-hex)
 *   --pr <id>          Pull request id for a pr event            (default: 1)
 *   -h, --help         Show this help
 */

function parseArgs(argv) {
  const args = { url: "http://localhost:3000", event: "push", branch: "main" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === "--url") args.url = next();
    else if (a === "--secret") args.secret = next();
    else if (a === "--repo-id") args.repoId = next();
    else if (a === "--event") args.event = next();
    else if (a === "--branch") args.branch = next();
    else if (a === "--commit") args.commit = next();
    else if (a === "--pr") args.pr = next();
    else if (a === "-h" || a === "--help") args.help = true;
  }
  return args;
}

function randomSha() {
  const hex = "0123456789abcdef";
  let s = "";
  for (let i = 0; i < 40; i++) s += hex[Math.floor(Math.random() * 16)];
  return s;
}

function pushPayload({ repoId, branch, commit }) {
  return {
    eventType: "git.push",
    resource: {
      refUpdates: [
        { name: `refs/heads/${branch}`, newObjectId: commit || randomSha() },
      ],
      repository: { id: repoId, name: "test-repo" },
    },
  };
}

function prPayload({ repoId, branch, commit, pr }) {
  const head = commit || randomSha();
  return {
    eventType: "git.pullrequest.updated",
    resource: {
      pullRequestId: Number(pr) || 1,
      sourceRefName: `refs/heads/${branch}`,
      lastMergeSourceCommit: { commitId: head },
      lastMergeTargetCommit: { commitId: randomSha() },
      repository: { id: repoId, name: "test-repo" },
    },
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(
      "Usage: node scripts/ado-webhook-test.mjs --repo-id <guid> [--url <base>] [--secret <value>] [--event push|pr] [--branch <name>] [--commit <sha>] [--pr <id>]",
    );
    process.exit(0);
  }

  const secret = args.secret || process.env.AZURE_DEVOPS_WEBHOOK_SECRET;
  if (!args.repoId) {
    console.error(
      "Error: --repo-id is required (the ADO repository GUID of a connected Pepper project).",
    );
    process.exit(2);
  }
  if (!secret) {
    console.error(
      "Error: webhook secret required via --secret or AZURE_DEVOPS_WEBHOOK_SECRET. It must match the 'Azure DevOps basic auth password' set in Pepper (Settings → Integrations → Webhook secrets).",
    );
    process.exit(2);
  }

  const payload =
    args.event === "pr" ? prPayload(args) : pushPayload(args);
  const endpoint = `${args.url.replace(/\/+$/, "")}/api/webhooks/azure-devops`;
  // ADO service hooks authenticate with HTTP Basic auth; Pepper verifies the
  // PASSWORD against the configured secret (username is ignored).
  const authorization =
    "Basic " + Buffer.from(`pepper:${secret}`).toString("base64");

  console.log(`→ POST ${endpoint}`);
  console.log(`  event: ${payload.eventType}  repo-id: ${args.repoId}`);

  let res;
  try {
    res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: authorization,
      },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    console.error(`✗ Request failed: ${err?.message || err}`);
    console.error("  Is Pepper running and reachable at --url?");
    process.exit(1);
  }

  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }

  console.log(`← ${res.status} ${res.statusText}`);
  console.log(typeof body === "string" ? body : JSON.stringify(body, null, 2));

  if (res.status === 401) {
    console.error(
      "\n✗ 401 Unauthorized — the secret does not match Pepper's stored 'Azure DevOps basic auth password'.",
    );
    process.exit(1);
  }
  if (body && typeof body === "object" && body.scanId) {
    console.log(
      `\n✓ Scan queued (${body.status}). Open Pepper → Scans to watch it run; for a PR event, the status check + inline comments post back once it completes.`,
    );
  } else {
    console.log(
      "\nℹ No scan was queued. Common causes: no connected project matches this repo-id, or (push) the branch is not the project's default branch.",
    );
  }
}

main();
