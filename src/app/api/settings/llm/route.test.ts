import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const getActiveOrgId = vi.fn(async () => "active-org");
const requireRole = vi.fn();
vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getActiveOrgId: () => getActiveOrgId(),
  getDefaultOrgId: vi.fn(() => "first-org"),
  requireRole: (...a: unknown[]) => requireRole(...a),
}));

const findUnique = vi.fn();
const upsert = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: {
    orgSettings: {
      findUnique: (...a: unknown[]) => findUnique(...a),
      upsert: (...a: unknown[]) => upsert(...a),
    },
  },
}));
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: vi.fn(), ipFromHeaders: vi.fn() }));
vi.mock("@/lib/token-encryption", () => ({ encryptSecret: (s: string) => `E(${s})` }));
vi.mock("@/lib/llm-redaction", () => ({ llmMaskingEnabled: () => false }));
vi.mock("@/lib/llm-exclusions", () => ({
  BUILTIN_LLM_EXCLUDES: [],
  configuredLlmExcludes: () => [],
}));

import { GET, PUT } from "./route";

beforeEach(() => {
  vi.clearAllMocks();
  getActiveOrgId.mockResolvedValue("active-org");
  requireRole.mockResolvedValue({ session: { user: { id: "u1" } } });
  findUnique.mockResolvedValue(null);
  upsert.mockResolvedValue({});
});

describe("GET /api/settings/llm", () => {
  it("reads the ACTIVE org's settings", async () => {
    await GET();
    expect(getActiveOrgId).toHaveBeenCalled();
    expect(findUnique).toHaveBeenCalledWith({
      where: { organizationId: "active-org" },
    });
  });
});

describe("PUT /api/settings/llm", () => {
  it("writes to the ACTIVE org's settings and role-checks that org", async () => {
    const req = new NextRequest("http://localhost/api/settings/llm", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ llmModel: "z-ai/glm-5.3" }),
    });

    const res = (await PUT(req))!;

    expect(res.status).toBe(200);
    expect(requireRole).toHaveBeenCalledWith("active-org", "ADMIN");
    expect(upsert).toHaveBeenCalledWith(
      expect.objectContaining({ where: { organizationId: "active-org" } }),
    );
  });
});
