import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  orgBitbucketConnection: { findUnique: vi.fn() },
  project: { findFirst: vi.fn(), findMany: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
vi.mock("./prisma", () => ({ prisma: db }));
vi.mock("./token-encryption", () => ({ decryptSecret: (s: string) => `plain:${s}`, encryptSecret: (s: string) => `enc:${s}` }));

import { bitbucketAuthHeader, withBitbucketAuth } from "./bitbucket-api";
import { getOrgBitbucketAuth, getOrgBitbucketAuthOrThrow } from "./bitbucket-connection";
import { findProjectForBitbucketWebhook } from "./bitbucket-webhook-scan";
import { authenticatedRepoUrl, credentialsMismatch } from "./remediation/repo-target";

const access = { username: "", appPassword: "", token: "ATCTT-s3cr3t", authType: "access_token" as const };
const apiToken = { ...access, token: "ATATT-s3cr3t", authType: "api_token" as const };
const legacy = { username: "alice", appPassword: "pw" };

beforeEach(() => vi.clearAllMocks());

describe("Bitbucket credentials", () => {
  it("sends tokens as Bearer and app passwords as Basic", () => {
    expect(bitbucketAuthHeader(access)).toBe("Bearer ATCTT-s3cr3t");
    expect(bitbucketAuthHeader(legacy)).toBe(`Basic ${Buffer.from("alice:pw").toString("base64")}`);
  });

  it("uses Bitbucket's git usernames for tokens, only on bitbucket.org", () => {
    expect(withBitbucketAuth("https://bitbucket.org/acme/api.git", access)).toBe("https://x-token-auth:ATCTT-s3cr3t@bitbucket.org/acme/api.git");
    expect(withBitbucketAuth("https://alice@bitbucket.org/acme/api.git", apiToken)).toBe("https://x-bitbucket-api-token-auth:ATATT-s3cr3t@bitbucket.org/acme/api.git");
    expect(withBitbucketAuth("https://bitbucket.org/acme/api.git", legacy)).toBe("https://alice:pw@bitbucket.org/acme/api.git");
    expect(withBitbucketAuth("https://bitbucket.org.evil.net/acme/api.git", access)).toBeNull();
    expect(withBitbucketAuth("http://bitbucket.org/acme/api.git", access)).toBeNull();
    expect(withBitbucketAuth("https://git.corp/acme/api.git", legacy)).toBeNull();
  });

  it("reads token connections, and legacy app-password ones as before", async () => {
    db.orgBitbucketConnection.findUnique.mockResolvedValue({ username: "acme access token", authType: "access_token", tokenEnc: "t", appPasswordEnc: null });
    expect(await getOrgBitbucketAuth("o1")).toEqual({ username: "acme access token", appPassword: "", token: "plain:t", authType: "access_token" });
    db.orgBitbucketConnection.findUnique.mockResolvedValue({ username: "alice", authType: "app_password", tokenEnc: null, appPasswordEnc: "p" });
    expect(await getOrgBitbucketAuth("o1")).toEqual({ username: "alice", appPassword: "plain:p" });
  });

  it("checks a token connection against its workspace, not /user (bots can't read it)", async () => {
    db.orgBitbucketConnection.findUnique
      .mockResolvedValueOnce({ username: "bot", authType: "access_token", tokenEnc: "t", appPasswordEnc: null })
      .mockResolvedValueOnce({ workspace: "acme" });
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));
    await getOrgBitbucketAuthOrThrow("o1");
    expect(String(f.mock.calls[0][0])).toBe("https://api.bitbucket.org/2.0/repositories/acme?pagelen=1");
    f.mockRestore();
  });

  it("remediation: tokens only for bitbucket.org", () => {
    const creds = { provider: "bitbucket" as const, auth: access };
    expect(credentialsMismatch("https://bitbucket.org/acme/api.git", creds)).toBeNull();
    expect(credentialsMismatch("https://git.corp/acme/api.git", creds)).toMatch(/only sent to https:\/\/bitbucket.org/);
    expect(authenticatedRepoUrl("https://bitbucket.org/acme/api.git", creds)).toBe("https://x-token-auth:ATCTT-s3cr3t@bitbucket.org/acme/api.git");
    // App passwords as before.
    expect(credentialsMismatch("https://bitbucket.org/acme/api.git", { provider: "bitbucket", auth: legacy })).toBeNull();
    expect(authenticatedRepoUrl("https://bitbucket.org/acme/api.git", { provider: "bitbucket", auth: legacy })).toBe("https://alice:pw@bitbucket.org/acme/api.git");
  });
});

describe("finding the project for a Bitbucket event", () => {
  const p = (id: string, repoUrl: string) => ({ id, repoUrl });

  it("matches the repository uuid first", async () => {
    db.project.findFirst.mockResolvedValue(p("by-uuid", "https://bitbucket.org/acme/renamed"));
    expect((await findProjectForBitbucketWebhook({ fullName: "acme/api", repoUuid: "{u1}", organizationId: "o1" }))!.id).toBe("by-uuid");
    expect(db.project.findFirst.mock.calls[0][0]).toMatchObject({ where: { bitbucketRepoUuid: "u1", organizationId: "o1" } });
  });

  it("then the whole workspace/slug only", async () => {
    db.project.findFirst.mockResolvedValue(null);
    db.project.findMany.mockResolvedValue([p("legacy", "https://bitbucket.org/acme/api-legacy"), p("right", "https://alice@bitbucket.org/acme/api.git")]);
    expect((await findProjectForBitbucketWebhook({ fullName: "acme/api", repoUuid: "{u1}", organizationId: "o1" }))!.id).toBe("right");
    db.project.findMany.mockResolvedValue([p("legacy", "https://bitbucket.org/acme/api-legacy")]);
    expect(await findProjectForBitbucketWebhook({ fullName: "acme/api", organizationId: "o1" })).toBeNull();
    db.project.findMany.mockResolvedValue([p("ssh", "git@bitbucket.org:acme/api.git")]);
    expect((await findProjectForBitbucketWebhook({ fullName: "acme/api" }))!.id).toBe("ssh");
  });
});
