import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const auth = vi.hoisted(() => ({ result: { ok: true, organizationId: "o1" } as { ok: boolean; organizationId?: string | null } }));
vi.mock("@/lib/webhook-secrets", () => ({ requireBitbucketWebhookAuth: async () => auth.result }));
const find = vi.hoisted(() => vi.fn());
const queue = vi.hoisted(() => vi.fn(async (_p: Record<string, unknown>) => ({ scanId: "s1", status: "QUEUED" })));
vi.mock("@/lib/bitbucket-webhook-scan", async (orig) => ({
  ...(await orig<typeof import("@/lib/bitbucket-webhook-scan")>()),
  findProjectForBitbucketWebhook: (...a: unknown[]) => find(...a),
  queueBitbucketWebhookScan: (p: Record<string, unknown>) => queue(p),
  mainBranchWebhookScanType: () => "SAST_ONLY",
}));
const bot = vi.hoisted(() => ({
  ensure: vi.fn(async (..._a: unknown[]) => true),
  pr: vi.fn(async (..._a: unknown[]) => ({ message: "Review queued" })),
  comment: vi.fn(async (..._a: unknown[]) => ({ message: "pause" })),
}));
vi.mock("@/lib/pr-review/bitbucket", () => ({
  ensureProjectForBitbucketRepo: (...a: unknown[]) => bot.ensure(...a),
  handleBitbucketPullRequest: (...a: unknown[]) => bot.pr(...a),
  handleBitbucketComment: (...a: unknown[]) => bot.comment(...a),
}));

import { POST } from "./route";

const project = { id: "p1", organizationId: "o1", repoUrl: "https://bitbucket.org/acme/api.git", defaultBranch: "main" };
const repository = { full_name: "acme/api", uuid: "{u1}", is_private: true };
const post = async (eventKey: string, body: unknown) =>
  (await POST(new NextRequest("http://localhost/api/webhooks/bitbucket", { method: "POST", headers: { "x-event-key": eventKey }, body: JSON.stringify(body) })))!.json();

beforeEach(() => {
  vi.clearAllMocks();
  auth.result = { ok: true, organizationId: "o1" };
  find.mockResolvedValue(project);
});

describe("Bitbucket webhook", () => {
  it("still scans pushes to the default branch only", async () => {
    const push = (name: string) => ({ repository, push: { changes: [{ new: { type: "branch", name, target: { hash: "abc" } } }] } });
    expect(await post("repo:push", push("main"))).toMatchObject({ trigger: "push_default_branch" });
    expect(queue.mock.calls[0][0]).toMatchObject({ scanType: "SAST_ONLY", branch: "main", commitSha: "abc", repoUrl: "https://bitbucket.org/acme/api.git" });
    expect(await post("repo:push", push("feature"))).toEqual({ message: "Event ignored" });
  });

  it("hands PR and comment events to the review bot", async () => {
    expect(await post("pullrequest:created", { repository, pullrequest: { id: 12 } })).toEqual({ message: "Review queued" });
    expect(bot.pr.mock.calls[0].slice(1)).toEqual(["acme/api", "pullrequest:created", { id: 12 }]);
    expect(await post("pullrequest:comment_created", { repository, pullrequest: { id: 12 }, comment: { id: 1 } })).toEqual({ message: "pause" });
    expect(await post("pullrequest:fulfilled", { repository, pullrequest: { id: 12 } })).toEqual({ message: "Event ignored" });
  });

  it("onboards unknown repositories from an organization's webhook, not from comments or the env-only secret", async () => {
    find.mockResolvedValueOnce(null).mockResolvedValueOnce(project);
    await post("pullrequest:created", { repository, pullrequest: { id: 12 } });
    expect(bot.ensure).toHaveBeenCalledWith("o1", repository);

    vi.clearAllMocks();
    find.mockResolvedValue(null);
    expect(await post("pullrequest:comment_created", { repository, pullrequest: { id: 12 }, comment: { id: 1 } })).toEqual({ message: "No matching project found" });
    auth.result = { ok: true, organizationId: null };
    await post("pullrequest:created", { repository, pullrequest: { id: 12 } });
    expect(bot.ensure).not.toHaveBeenCalled();
  });
});
