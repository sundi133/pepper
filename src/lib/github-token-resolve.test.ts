import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  orgGithubAppInstallation: { findMany: vi.fn(), deleteMany: vi.fn(async (_a: unknown) => ({ count: 1 })), updateMany: vi.fn(async (_a: unknown) => ({ count: 1 })) },
  orgGithubConnection: { findUnique: vi.fn() },
}));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
vi.mock("@/lib/token-encryption", () => ({ decryptSecret: (s: string) => s.replace(/^enc:/, "") }));
const app = vi.hoisted(() => ({ config: vi.fn(), token: vi.fn() }));
vi.mock("@/lib/github-app", () => ({
  githubAppConfig: () => app.config(),
  getInstallationToken: (...a: unknown[]) => app.token(...a),
  forgetInstallationToken: vi.fn(),
}));

import { resolveGithubToken } from "./github-token-resolve";
import { getOrgGithubAccessToken } from "./github-connection";

const CFG = { appId: "1" };
const inst = (login: string, id: number) => ({ id: `row-${id}`, installationId: BigInt(id), accountLogin: login });

beforeEach(() => {
  vi.clearAllMocks();
  app.config.mockReturnValue(CFG);
  app.token.mockImplementation(async (_c: unknown, id: bigint) => ({ ok: true, token: `ghs_${id}`, expiresAt: 0 }));
  db.orgGithubAppInstallation.findMany.mockResolvedValue([inst("Acme", 1), inst("acme-labs", 2)]);
  db.orgGithubConnection.findUnique.mockResolvedValue({ accessTokenEnc: "enc:gho_personal" });
});

describe("resolveGithubToken", () => {
  it("uses the installation for the repository's owner, case-insensitively", async () => {
    expect(await resolveGithubToken("o1", { owner: "ACME", name: "api" })).toEqual({ token: "ghs_1", source: "app", installationId: BigInt(1) });
    expect(await resolveGithubToken("o1", { owner: "acme-labs" })).toMatchObject({ token: "ghs_2", source: "app" });
    expect(db.orgGithubAppInstallation.findMany.mock.calls[0][0].where).toEqual({ organizationId: "o1", suspendedAt: null });
  });

  it("falls back to the OAuth connection for owners without an installation", async () => {
    expect(await resolveGithubToken("o1", { owner: "someone-else", name: "x" })).toEqual({ token: "gho_personal", source: "oauth" });
  });

  it("behaves exactly as before when the App isn't configured: OAuth, and no installation lookup", async () => {
    app.config.mockReturnValue(null);
    expect(await resolveGithubToken("o1", { owner: "Acme" })).toEqual({ token: "gho_personal", source: "oauth" });
    expect(await getOrgGithubAccessToken("o1")).toBe("gho_personal");
    expect(db.orgGithubAppInstallation.findMany).not.toHaveBeenCalled();
    db.orgGithubConnection.findUnique.mockResolvedValue(null);
    expect(await getOrgGithubAccessToken("o1")).toBeNull();
  });

  it("without a repository, prefers OAuth, then the only installation", async () => {
    expect(await resolveGithubToken("o1", null)).toMatchObject({ source: "oauth" });
    db.orgGithubConnection.findUnique.mockResolvedValue(null);
    expect(await resolveGithubToken("o1", null)).toBeNull(); // two installations: ambiguous
    db.orgGithubAppInstallation.findMany.mockResolvedValue([inst("Acme", 1)]);
    expect(await resolveGithubToken("o1", null)).toMatchObject({ token: "ghs_1", source: "app" });
  });

  it("unlinks an installation GitHub says is gone and falls back to OAuth", async () => {
    app.token.mockResolvedValue({ ok: false, reason: "removed", status: 404 });
    expect(await resolveGithubToken("o1", { owner: "acme" })).toEqual({ token: "gho_personal", source: "oauth" });
    expect(db.orgGithubAppInstallation.deleteMany).toHaveBeenCalledWith({ where: { id: "row-1" } });
  });

  it("marks a suspended installation and uses OAuth meanwhile", async () => {
    app.token.mockResolvedValue({ ok: false, reason: "suspended", status: 403 });
    expect(await resolveGithubToken("o1", { owner: "acme" })).toMatchObject({ source: "oauth" });
    expect(db.orgGithubAppInstallation.updateMany.mock.calls[0][0]).toMatchObject({ where: { id: "row-1" }, data: { suspendedAt: expect.any(Date) } });
  });

  it("returns nothing when neither is available", async () => {
    db.orgGithubConnection.findUnique.mockResolvedValue(null);
    expect(await resolveGithubToken("o1", { owner: "other" })).toBeNull();
  });
});
