import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  requireRole: vi.fn(async () => ({ session: {}, membership: { role: "ADMIN" } })),
}));
const saveToken = vi.hoisted(() => vi.fn(async (_a: Record<string, unknown>) => undefined));
const saveLegacy = vi.hoisted(() => vi.fn(async (_a: Record<string, unknown>) => undefined));
vi.mock("@/lib/bitbucket-connection", () => ({
  saveOrgBitbucketConnection: (a: Record<string, unknown>) => saveLegacy(a),
  saveOrgBitbucketTokenConnection: (a: Record<string, unknown>) => saveToken(a),
  deleteOrgBitbucketConnection: vi.fn(),
  getBitbucketConnectionStatus: vi.fn(),
}));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: vi.fn(async () => undefined), ipFromHeaders: vi.fn(() => null) }));
const get = vi.hoisted(() => vi.fn());
vi.mock("@/lib/bitbucket-api", () => ({ bitbucketGet: (...a: unknown[]) => get(...a) }));

import { POST } from "./route";

const post = async (body: unknown) => {
  const res = await POST(new NextRequest("http://localhost/api/integrations/bitbucket/connect", { method: "POST", body: JSON.stringify(body) }));
  return { status: res!.status, body: await res!.json() };
};

beforeEach(() => vi.clearAllMocks());

describe("Bitbucket connect with a token", () => {
  it("verifies an access token against the workspace and saves it, even when /user is refused", async () => {
    get.mockImplementation(async (_a: unknown, path: string) => (path === "/user" ? { ok: false, status: 403, data: {}, raw: "" } : { ok: true, status: 200, data: { values: [] }, raw: "" }));
    const r = await post({ authType: "access_token", token: "ATCTT-x", workspace: "acme" });
    expect(r).toMatchObject({ status: 200, body: { connected: true, username: "acme access token", authType: "access_token" } });
    expect(get.mock.calls[0][0]).toEqual({ username: "", appPassword: "", token: "ATCTT-x", authType: "access_token" });
    expect(get.mock.calls[0][1]).toBe("/repositories/acme?pagelen=1");
    expect(saveToken).toHaveBeenCalledWith({ organizationId: "o1", authType: "access_token", token: "ATCTT-x", username: "acme access token", workspace: "acme" });
    expect(saveLegacy).not.toHaveBeenCalled();
  });

  it("explains a rejected token and never echoes it", async () => {
    get.mockResolvedValue({ ok: false, status: 401, data: {}, raw: "" });
    const r = await post({ authType: "api_token", token: "ATATT-secret", workspace: "acme" });
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/rejected the API token for workspace acme/);
    expect(JSON.stringify(r.body)).not.toContain("ATATT-secret");
    expect(saveToken).not.toHaveBeenCalled();
  });

  it("requires a token and a valid workspace slug", async () => {
    expect((await post({ authType: "access_token", token: "", workspace: "acme" })).status).toBe(400);
    expect((await post({ authType: "access_token", token: "t", workspace: "a/b" })).status).toBe(400);
    expect(get).not.toHaveBeenCalled();
  });

  it("still accepts the legacy username and app password", async () => {
    get.mockResolvedValue({ ok: true, status: 200, data: { username: "alice" }, raw: "" });
    expect((await post({ username: "alice", appPassword: "pw", workspace: "acme" })).status).toBe(200);
    expect(saveLegacy).toHaveBeenCalledWith({ organizationId: "o1", username: "alice", appPassword: "pw", workspace: "acme" });
  });
});
