import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const session = vi.hoisted(() => ({ value: { user: { id: "u1" } } as { user: { id: string } } | null }));
vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => (session.value ? { session: session.value } : { error: new Response(null, { status: 401 }) })),
  getDefaultOrgId: vi.fn(() => "o1"),
  requireRole: vi.fn(async () => ({ session: {}, membership: { role: "SECURITY" } })),
}));
const cookieJar = vi.hoisted(() => ({ value: "state-ok" as string | undefined, set: vi.fn() }));
vi.mock("next/headers", () => ({ cookies: async () => ({ get: () => (cookieJar.value ? { value: cookieJar.value } : undefined), set: cookieJar.set }) }));
const state = vi.hoisted(() => ({ verify: vi.fn() }));
vi.mock("@/lib/github-oauth-state", () => ({ verifyGithubOAuthState: (...a: unknown[]) => state.verify(...a), oauthStateCookieOptions: () => ({}) }));
const gh = vi.hoisted(() => ({ exchange: vi.fn(), canAccess: vi.fn(), getInstallation: vi.fn(), config: vi.fn() }));
vi.mock("@/lib/github-app", () => ({
  GITHUB_APP_STATE_COOKIE: "pepper_github_app_state",
  githubAppConfig: () => gh.config(),
  exchangeAppUserCode: (...a: unknown[]) => gh.exchange(...a),
  userCanAccessInstallation: (...a: unknown[]) => gh.canAccess(...a),
  getInstallation: (...a: unknown[]) => gh.getInstallation(...a),
}));
const db = vi.hoisted(() => ({ orgGithubAppInstallation: { findUnique: vi.fn(), upsert: vi.fn(async (_args: unknown) => ({})) } }));
vi.mock("@/lib/prisma", () => ({ prisma: db }));
const audit = vi.hoisted(() => vi.fn(async (_entry: unknown) => undefined));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: audit, ipFromHeaders: () => "1.2.3.4" }));

import { GET } from "./route";

const call = async (q: string) => {
  const res = await GET(new NextRequest(`http://localhost/api/integrations/github/app/setup?${q}`));
  const loc = new URL(res.headers.get("location")!);
  return { status: loc.searchParams.get("githubApp"), message: loc.searchParams.get("message") ?? "" };
};
const OK = "installation_id=42&setup_action=install&code=c0de&state=state-ok";

beforeEach(() => {
  vi.clearAllMocks();
  session.value = { user: { id: "u1" } };
  cookieJar.value = "state-ok";
  process.env.NEXTAUTH_URL = "https://pepper.example";
  gh.config.mockReturnValue({ appId: "1" });
  state.verify.mockReturnValue({ orgId: "o1", userId: "u1", nonce: "n", exp: 9e9 });
  gh.exchange.mockResolvedValue("ghu_user");
  gh.canAccess.mockResolvedValue(true);
  gh.getInstallation.mockResolvedValue({ id: 42, account: { login: "acme", type: "Organization" }, repository_selection: "selected", suspended_at: null });
  db.orgGithubAppInstallation.findUnique.mockResolvedValue(null);
});

describe("GitHub App setup callback", () => {
  it("links the installation after every check passes, and audits it", async () => {
    expect(await call(OK)).toEqual({ status: "installed", message: "" });
    expect(gh.canAccess).toHaveBeenCalledWith("ghu_user", 42);
    expect(db.orgGithubAppInstallation.upsert.mock.calls[0][0]).toMatchObject({
      where: { installationId: BigInt(42) },
      create: { organizationId: "o1", installationId: BigInt(42), accountLogin: "acme", accountType: "Organization", repositorySelection: "selected", createdBy: "u1" },
    });
    expect(audit.mock.calls[0][0]).toMatchObject({ action: "github_app.installed" });
    expect(cookieJar.set).toHaveBeenCalled(); // state cookie cleared
  });

  it("refuses when the person who installed can't access the installation (an edited installation_id)", async () => {
    gh.canAccess.mockResolvedValue(false);
    expect((await call(OK)).status).toBe("error");
    expect(db.orgGithubAppInstallation.upsert).not.toHaveBeenCalled();
    expect(audit.mock.calls[0][0]).toMatchObject({ action: "github_app.link_refused" });
    gh.exchange.mockResolvedValue(null);
    expect((await call(OK)).status).toBe("error");
  });

  it("refuses an installation already linked to another organization", async () => {
    db.orgGithubAppInstallation.findUnique.mockResolvedValue({ organizationId: "o-other" });
    const r = await call(OK);
    expect(r.status).toBe("error");
    expect(r.message).toMatch(/another Pepper organization/);
    expect(db.orgGithubAppInstallation.upsert).not.toHaveBeenCalled();
  });

  it("refuses without Pepper's state, for another user, or without a code", async () => {
    state.verify.mockReturnValue(null);
    expect((await call(OK)).message).toMatch(/Start the installation from Pepper/);
    state.verify.mockReturnValue({ orgId: "o1", userId: "someone-else", nonce: "n", exp: 9e9 });
    expect((await call(OK)).message).toMatch(/different user/);
    state.verify.mockReturnValue({ orgId: "o1", userId: "u1", nonce: "n", exp: 9e9 });
    expect((await call("installation_id=42&state=state-ok")).status).toBe("error");
    expect((await call("installation_id=abc&code=c&state=state-ok")).status).toBe("error");
    expect(db.orgGithubAppInstallation.upsert).not.toHaveBeenCalled();
  });

  it("explains requests awaiting an owner's approval and an unconfigured App", async () => {
    expect((await call("setup_action=request&state=state-ok")).message).toMatch(/owner must approve/);
    gh.config.mockReturnValue(null);
    expect((await call(OK)).message).toMatch(/not configured/);
  });
});
