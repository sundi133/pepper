import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
  requireRole: vi.fn(async () => ({ session: {}, membership: { role: "ADMIN" } })),
}));
const save = vi.fn(async () => undefined);
vi.mock("@/lib/azure-devops-connection", () => ({
  saveOrgAzureDevOpsConnection: (...a: unknown[]) => save(...(a as [])),
  deleteOrgAzureDevOpsConnection: vi.fn(),
  getAzureDevOpsConnectionStatus: vi.fn(),
}));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: vi.fn(async () => undefined), ipFromHeaders: vi.fn(() => null) }));
const azureGet = vi.fn();
vi.mock("@/lib/azure-devops-api", () => ({ azureGet: (...a: unknown[]) => azureGet(...a) }));

import { POST } from "./route";

const post = (body: unknown) =>
  POST(new NextRequest("http://localhost/api/integrations/azure-devops/connect", { method: "POST", body: JSON.stringify(body) }));

beforeEach(() => vi.clearAllMocks());

describe("Azure DevOps connect", () => {
  it("answers with a readable JSON error when the server can't be reached", async () => {
    azureGet.mockRejectedValue(
      Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new AggregateError([]), { code: "ECONNREFUSED" }) }),
    );
    const res = await post({ azureOrganization: "DefaultCollection", pat: "p", azureServerUrl: "http://localhost:18080" });
    expect(res!.status).toBe(502);
    const body = await res!.json();
    expect(body.error).toMatch(/Could not connect to localhost:18080: connection refused/);
    expect(body.error).toMatch(/"localhost" is Pepper itself/);
    expect(save).not.toHaveBeenCalled();
  });

  it("still saves a connection that answers", async () => {
    azureGet.mockResolvedValue({ ok: true, status: 200, data: { authenticatedUser: { providerDisplayName: "adoadmin" } }, raw: "" });
    const res = await post({ azureOrganization: "DefaultCollection", pat: "p", azureServerUrl: "http://ado-server" });
    expect(res!.status).toBe(200);
    expect(save).toHaveBeenCalledTimes(1);
  });

  it("still reports rejected credentials as before", async () => {
    azureGet.mockResolvedValue({ ok: false, status: 401, data: {}, raw: "" });
    const res = await post({ azureOrganization: "DefaultCollection", pat: "bad", azureServerUrl: "http://ado-server" });
    expect((await res!.json()).error).toMatch(/rejected the credentials/);
  });
});
