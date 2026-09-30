import { describe, expect, it, vi } from "vitest";
import {
  entraEmail,
  entraProvider,
  hasGroupsOverage,
  readEntraConfig,
  resolveEntraAccess,
  type EntraClaims,
  type EntraConfig,
} from "./entra";

const TENANT = "11111111-2222-3333-4444-555555555555";
const ADMINS = "aaaaaaaa-0000-0000-0000-000000000001";
const APPSEC = "aaaaaaaa-0000-0000-0000-000000000002";
const env = {
  ENABLE_ENTRA_SSO: "true",
  ENTRA_TENANT_ID: TENANT,
  ENTRA_CLIENT_ID: "client",
  ENTRA_CLIENT_SECRET: "secret",
  ENTRA_ROLE_MAP: JSON.stringify({ [ADMINS]: "ADMIN", [APPSEC]: "SECURITY", "Pepper.Developer": "DEVELOPER" }),
};
const cfg = readEntraConfig(env) as EntraConfig;
const claims = (over: Partial<EntraClaims> = {}): EntraClaims => ({
  sub: "s",
  oid: "o1",
  tid: TENANT,
  email: "Ann@Acme.com",
  name: "Ann",
  ...over,
});

describe("config", () => {
  it("is off unless enabled, and refuses multi-tenant authorities", () => {
    expect(readEntraConfig({})).toBeNull();
    expect(readEntraConfig({ ...env, ENTRA_CLIENT_SECRET: "" })).toEqual({ error: expect.stringMatching(/required/) });
    for (const t of ["common", "organizations", "Consumers"]) {
      expect(readEntraConfig({ ...env, ENTRA_TENANT_ID: t })).toEqual({ error: expect.stringMatching(/not "/) });
    }
  });

  it("defaults to raise-only role sync, viewer role and the public cloud", () => {
    expect(cfg).toMatchObject({
      roleSync: "raise",
      requireRole: false,
      allowGuests: false,
      defaultRole: "VIEWER",
      authorityHost: "https://login.microsoftonline.com",
      graphUrl: "https://graph.microsoft.com",
      overageLookup: true,
    });
    const gov = readEntraConfig({ ...env, ENTRA_AUTHORITY_HOST: "https://login.microsoftonline.us/", ENTRA_ROLE_SYNC: "exact" }) as EntraConfig;
    expect(gov).toMatchObject({ authorityHost: "https://login.microsoftonline.us", roleSync: "exact" });
  });

  it("pins the provider to the tenant's issuer with PKCE, state and nonce", () => {
    const p = entraProvider(cfg);
    expect(p.wellKnown).toBe(`https://login.microsoftonline.com/${TENANT}/v2.0/.well-known/openid-configuration`);
    expect(p.checks).toEqual(["pkce", "state", "nonce"]);
    expect(p.idToken).toBe(true);
    expect(p.profile!(claims({ oid: "oid-1" }), {})).toEqual({ id: "oid-1", name: "Ann", email: "ann@acme.com", image: null });
  });
});

describe("claims", () => {
  it("uses email, else the UPN", () => {
    expect(entraEmail(claims())).toBe("ann@acme.com");
    expect(entraEmail(claims({ email: undefined, preferred_username: "Ann@corp.onmicrosoft.com" }))).toBe("ann@corp.onmicrosoft.com");
    expect(entraEmail(claims({ email: undefined, preferred_username: "not-an-email" }))).toBeNull();
  });

  it("detects groups overage", () => {
    expect(hasGroupsOverage(claims({ _claim_names: { groups: "src1" } }))).toBe(true);
    expect(hasGroupsOverage(claims({ hasgroups: true }))).toBe(true);
    expect(hasGroupsOverage(claims({ groups: [] }))).toBe(false);
  });
});

describe("resolveEntraAccess", () => {
  it("maps the highest app role or group", async () => {
    await expect(resolveEntraAccess(claims({ roles: ["Pepper.Developer"], groups: [APPSEC] }), undefined, cfg)).resolves.toEqual({
      allowed: true,
      role: "SECURITY",
      matched: ["Pepper.Developer", APPSEC],
    });
    await expect(resolveEntraAccess(claims({ groups: ["unmapped"] }), undefined, cfg)).resolves.toMatchObject({ allowed: true, role: "VIEWER" });
  });

  it("can require an assignment", async () => {
    const strict = { ...cfg, requireRole: true };
    await expect(resolveEntraAccess(claims({ groups: ["unmapped"] }), undefined, strict)).resolves.toEqual({ allowed: false, reason: "no_role" });
  });

  it("refuses other tenants, guests and accounts without an email", async () => {
    await expect(resolveEntraAccess(claims({ tid: "99999999-2222-3333-4444-555555555555" }), undefined, cfg)).resolves.toEqual({ allowed: false, reason: "tenant" });
    await expect(resolveEntraAccess(claims({ idp: "https://sts.windows.net/other/" }), undefined, cfg)).resolves.toEqual({ allowed: false, reason: "guest" });
    await expect(resolveEntraAccess(claims({ acct: 1 }), undefined, { ...cfg, allowGuests: true })).resolves.toMatchObject({ allowed: true });
    await expect(resolveEntraAccess(claims({ email: undefined, preferred_username: undefined }), undefined, cfg)).resolves.toEqual({ allowed: false, reason: "no_email" });
  });

  it("on overage, asks Graph about the mapped groups only", async () => {
    const fetchImpl = vi.fn(async (_url: string, init: RequestInit) => {
      const { groupIds } = JSON.parse(String(init.body)) as { groupIds: string[] };
      expect(groupIds.sort()).toEqual([ADMINS, APPSEC].sort());
      return Response.json({ value: [ADMINS] });
    });
    const res = await resolveEntraAccess(claims({ _claim_names: { groups: "src1" } }), "graph-token", cfg, fetchImpl as never);
    expect(res).toMatchObject({ allowed: true, role: "ADMIN" });
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://graph.microsoft.com/v1.0/me/checkMemberGroups",
      expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer graph-token" }) }),
    );
  });

  it("falls back to app roles when Graph is unreachable", async () => {
    const fetchImpl = vi.fn(async () => new Response("", { status: 403 }));
    const res = await resolveEntraAccess(claims({ roles: ["Pepper.Developer"], hasgroups: true }), "t", cfg, fetchImpl as never);
    expect(res).toMatchObject({ allowed: true, role: "DEVELOPER" });
  });
});
