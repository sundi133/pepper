import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  requireRole: vi.fn(async () => ({ session: {}, membership: { role: "SECURITY" } })),
}));
const conn = vi.hoisted(() => ({ saveSp: vi.fn(async (_a: Record<string, unknown>) => undefined), savePat: vi.fn(async (_a: unknown) => undefined) }));
vi.mock("@/lib/azure-devops-connection", () => ({
  saveOrgAzureDevOpsConnection: (a: unknown) => conn.savePat(a),
  saveOrgAzureDevOpsServicePrincipal: (a: Record<string, unknown>) => conn.saveSp(a),
  deleteOrgAzureDevOpsConnection: vi.fn(),
  getAzureDevOpsConnectionStatus: vi.fn(),
}));
const entra = vi.hoisted(() => vi.fn());
vi.mock("@/lib/azure-devops-entra", async (orig) => ({
  ...(await orig<typeof import("@/lib/azure-devops-entra")>()),
  getEntraAccessToken: (...a: unknown[]) => entra(...a),
}));
const probe = vi.hoisted(() => vi.fn());
vi.mock("@/lib/azure-devops-api", () => ({ azureGet: (...a: unknown[]) => probe(...a) }));
const audit = vi.hoisted(() => vi.fn(async (_e: { details: Record<string, unknown> }) => undefined));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: (e: { details: Record<string, unknown> }) => audit(e), ipFromHeaders: () => "1.2.3.4" }));

import { POST } from "./route";

const SP = { authType: "service_principal", azureOrganization: "contoso", tenantId: "contoso.onmicrosoft.com", clientId: "11111111-2222-3333-4444-555555555555", clientSecret: "s3cr3t~value" };
const post = async (body: unknown) => {
  const res = (await POST(new NextRequest("http://localhost/api/integrations/azure-devops/connect", { method: "POST", body: JSON.stringify(body) })))!;
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
};

beforeEach(() => {
  vi.clearAllMocks();
  entra.mockResolvedValue("eyJ.tok");
  probe.mockResolvedValue({ ok: true, status: 200, data: { authenticatedUser: { providerDisplayName: "Pepper SAST" } } });
});

describe("Azure DevOps service principal connection", () => {
  it("gets a token, checks it with Azure DevOps, then saves, without returning the secret", async () => {
    const r = await post(SP);
    expect(r).toMatchObject({ status: 200, body: { connected: true, authType: "service_principal", azureUser: "Pepper SAST" } });
    expect(JSON.stringify(r.body)).not.toContain(SP.clientSecret);
    expect(probe.mock.calls[0][0]).toEqual({ organization: "contoso", pat: "", bearer: "eyJ.tok" });
    expect(conn.saveSp.mock.calls[0][0]).toMatchObject({ organizationId: "o1", azureOrganization: "contoso", tenantId: SP.tenantId, clientId: SP.clientId, clientSecret: SP.clientSecret });
    expect(JSON.stringify(audit.mock.calls[0][0].details)).not.toContain(SP.clientSecret);
  });

  it("refuses missing fields, Azure DevOps Server and malformed ids", async () => {
    expect((await post({ ...SP, clientSecret: "" })).status).toBe(400);
    expect((await post({ ...SP, azureServerUrl: "https://tfs.corp" })).body.error).toMatch(/Services .* only/);
    expect((await post({ ...SP, clientId: "nope" })).body.error).toMatch(/GUID/);
    expect(conn.saveSp).not.toHaveBeenCalled();
  });

  it("explains Entra and Azure DevOps refusals and saves nothing", async () => {
    const { EntraTokenError } = await import("@/lib/azure-devops-entra");
    entra.mockRejectedValueOnce(new EntraTokenError("Entra ID refused the service principal: AADSTS7000215"));
    expect((await post(SP)).body.error).toMatch(/AADSTS7000215/);
    probe.mockResolvedValueOnce({ ok: false, status: 401, data: {} });
    expect((await post(SP)).body.error).toMatch(/Add it to the "contoso" organization/);
    expect(conn.saveSp).not.toHaveBeenCalled();
  });

  it("leaves the PAT path as it was", async () => {
    await post({ azureOrganization: "contoso", pat: "my-pat" });
    expect(probe.mock.calls[0][0]).toEqual({ organization: "contoso", pat: "my-pat" });
    expect(conn.savePat).toHaveBeenCalled();
    expect(entra).not.toHaveBeenCalled();
  });
});
