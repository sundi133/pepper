import { beforeEach, describe, expect, it, vi } from "vitest";
import { AZURE_DEVOPS_SCOPE, EntraTokenError, bearerGitEnv, clearEntraTokenCache, getEntraAccessToken, validServicePrincipalIds } from "./azure-devops-entra";
import { azureAuthHeader } from "./azure-devops-api";
import { boardsAuth } from "./integrations/azure-boards";

const SP = { tenantId: "contoso.onmicrosoft.com", clientId: "11111111-2222-3333-4444-555555555555", clientSecret: "s3cr3t~value" };
const json = (status: number, body: unknown) => ({ ok: status < 300, status, json: async () => body }) as unknown as Response;

beforeEach(() => clearEntraTokenCache());

describe("Entra ID service principal tokens", () => {
  it("uses client credentials for the Azure DevOps scope and caches until five minutes before expiry", async () => {
    const f = vi.fn(async () => json(200, { access_token: "eyJ.one", expires_in: 3600 }));
    const now = 1_000_000;
    expect(await getEntraAccessToken(SP, f as never, now)).toBe("eyJ.one");
    expect(await getEntraAccessToken(SP, f as never, now + 50 * 60_000)).toBe("eyJ.one");
    expect(f).toHaveBeenCalledTimes(1);
    const [url, init] = f.mock.calls[0] as unknown as [string, { body: string }];
    expect(url).toBe("https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token");
    const body = new URLSearchParams(init.body);
    expect(Object.fromEntries(body)).toMatchObject({ grant_type: "client_credentials", client_id: SP.clientId, scope: AZURE_DEVOPS_SCOPE });
    f.mockResolvedValueOnce(json(200, { access_token: "eyJ.two", expires_in: 3600 }));
    expect(await getEntraAccessToken(SP, f as never, now + 56 * 60_000)).toBe("eyJ.two");
  });

  it("reports Entra's reason and never the secret", async () => {
    const f = async () => json(401, { error: "invalid_client", error_description: `AADSTS7000215: Invalid client secret provided (${SP.clientSecret}).\nTrace ID: x` });
    const err = (await getEntraAccessToken(SP, f as never).catch((e: unknown) => e)) as EntraTokenError;
    expect(err).toBeInstanceOf(EntraTokenError);
    expect(err.message).toMatch(/AADSTS7000215/);
    expect(err.message).not.toContain(SP.clientSecret);
    expect(err.message).not.toMatch(/Trace ID/);
  });

  it("validates ids before calling Entra", async () => {
    expect(validServicePrincipalIds({ tenantId: "x", clientId: SP.clientId })).toMatch(/tenant/);
    expect(validServicePrincipalIds({ tenantId: SP.tenantId, clientId: "nope" })).toMatch(/GUID/);
    expect(validServicePrincipalIds({ tenantId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", clientId: SP.clientId })).toBeNull();
    const f = vi.fn();
    await expect(getEntraAccessToken({ ...SP, clientId: "nope" }, f as never)).rejects.toThrow(/GUID/);
    expect(f).not.toHaveBeenCalled();
  });

  it("sends the token as a header to git, never in the URL or arguments", () => {
    expect(bearerGitEnv("tok")).toEqual({ GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "http.extraHeader", GIT_CONFIG_VALUE_0: "Authorization: Bearer tok" });
  });
});

describe("auth headers", () => {
  it("uses Bearer for a service principal and Basic for a PAT", () => {
    expect(azureAuthHeader({ organization: "o", pat: "", bearer: "tok" })).toBe("Bearer tok");
    expect(azureAuthHeader({ organization: "o", pat: "p" })).toBe(`Basic ${Buffer.from(":p").toString("base64")}`);
  });

  it("lets Azure Boards reuse a service principal connection", () => {
    const viaSp = boardsAuth({ organization: "o", project: "P" } as never, { organization: "o", pat: "", bearer: "tok" });
    expect(viaSp).toMatchObject({ organization: "o", bearer: "tok" });
    const ownPat = boardsAuth({ organization: "o", project: "P", pat: "mine" } as never, { organization: "o", pat: "", bearer: "tok" });
    expect(ownPat).toMatchObject({ pat: "mine" });
    expect(ownPat?.bearer).toBeUndefined();
  });
});
