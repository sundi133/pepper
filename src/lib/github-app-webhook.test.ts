import { beforeEach, describe, expect, it, vi } from "vitest";
import { createHmac } from "crypto";

const db = vi.hoisted(() => ({
  orgGithubAppInstallation: { deleteMany: vi.fn(async (_a: unknown) => ({ count: 1 })), updateMany: vi.fn(async (_a: { data: { suspendedAt: Date | null } }) => ({ count: 1 })), findUnique: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
vi.mock("@/lib/github-app", () => ({ forgetInstallationToken: vi.fn() }));

import { authenticateAppWebhook, verifyAppWebhookSignature } from "./github-app-webhook";

const SECRET = "app-webhook-secret";
const signed = (payload: unknown, secret = SECRET) => {
  const body = JSON.stringify(payload);
  return { body, signature: `sha256=${createHmac("sha256", secret).update(body).digest("hex")}` };
};

beforeEach(() => vi.clearAllMocks());

describe("App webhooks", () => {
  it("verifies the App signature", () => {
    const { body, signature } = signed({ a: 1 });
    expect(verifyAppWebhookSignature(body, signature, SECRET)).toBe(true);
    expect(verifyAppWebhookSignature(body, signature, "other")).toBe(false);
    expect(verifyAppWebhookSignature(body, null, SECRET)).toBe(false);
    expect(verifyAppWebhookSignature(body, signature, null)).toBe(false);
  });

  it("leaves deliveries not signed by the App to the per-organization secrets", async () => {
    const { body, signature } = signed({ installation: { id: 1 } }, "an-org-secret");
    expect(await authenticateAppWebhook({ body, signature, event: "push", secret: SECRET })).toEqual({ kind: "not-app" });
    expect(await authenticateAppWebhook({ ...signed({}), event: "push", secret: undefined })).toEqual({ kind: "not-app" });
  });

  it("unlinks on uninstall and records suspension", async () => {
    const del = signed({ action: "deleted", installation: { id: 42 } });
    expect(await authenticateAppWebhook({ ...del, event: "installation", secret: SECRET })).toMatchObject({ kind: "handled" });
    expect(db.orgGithubAppInstallation.deleteMany).toHaveBeenCalledWith({ where: { installationId: BigInt(42) } });
    const sus = signed({ action: "suspend", installation: { id: 42 } });
    await authenticateAppWebhook({ ...sus, event: "installation", secret: SECRET });
    expect(db.orgGithubAppInstallation.updateMany.mock.calls[0]?.[0].data.suspendedAt).toBeInstanceOf(Date);
    const un = signed({ action: "unsuspend", installation: { id: 42 } });
    await authenticateAppWebhook({ ...un, event: "installation", secret: SECRET });
    expect(db.orgGithubAppInstallation.updateMany.mock.calls[1]?.[0].data.suspendedAt).toBeNull();
  });

  it("maps repository events to the linked organization only", async () => {
    db.orgGithubAppInstallation.findUnique.mockResolvedValue({ organizationId: "o1", suspendedAt: null });
    const push = signed({ installation: { id: 42 }, repository: { full_name: "acme/api" } });
    expect(await authenticateAppWebhook({ ...push, event: "push", secret: SECRET })).toEqual({ kind: "event", organizationId: "o1", installationId: BigInt(42) });
    db.orgGithubAppInstallation.findUnique.mockResolvedValue(null);
    expect(await authenticateAppWebhook({ ...push, event: "push", secret: SECRET })).toMatchObject({ kind: "handled", message: expect.stringMatching(/not linked/) });
    db.orgGithubAppInstallation.findUnique.mockResolvedValue({ organizationId: "o1", suspendedAt: new Date() });
    expect(await authenticateAppWebhook({ ...push, event: "push", secret: SECRET })).toMatchObject({ kind: "handled" });
  });
});
