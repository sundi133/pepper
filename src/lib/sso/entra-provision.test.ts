import { beforeEach, describe, expect, it, vi } from "vitest";

const members = new Map<string, string>(); // userId -> role
let adminCount = 1;
const audit: Array<Record<string, unknown>> = [];

vi.mock("@/lib/saml/provision", () => ({
  resolveTargetOrgId: vi.fn(async () => "org1"),
  provisionSamlUser: vi.fn(async ({ email, role }: { email: string; role: string }) => {
    const userId = email === "ann@acme.com" ? "u1" : "u2";
    // SAML semantics: create at `role`, or raise an existing lower role.
    const rank = ["VIEWER", "DEVELOPER", "SECURITY", "ADMIN"];
    const cur = members.get(userId);
    if (!cur || rank.indexOf(role) > rank.indexOf(cur)) members.set(userId, role);
    return { userId };
  }),
}));
vi.mock("@/lib/prisma", () => ({
  prisma: {
    orgMember: {
      findUnique: vi.fn(async ({ where }: { where: { userId_organizationId: { userId: string } } }) => {
        const role = members.get(where.userId_organizationId.userId);
        return role ? { role } : null;
      }),
      count: vi.fn(async () => adminCount),
      update: vi.fn(async ({ where, data }: { where: { userId_organizationId: { userId: string } }; data: { role: string } }) => {
        members.set(where.userId_organizationId.userId, data.role);
      }),
    },
    auditLog: { create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => audit.push(data)) },
  },
}));

import { provisionEntraUser } from "./entra-provision";
import type { EntraConfig } from "./entra";

const base = { defaultOrgSlug: "", roleSync: "raise" } as EntraConfig;

beforeEach(() => {
  members.clear();
  audit.length = 0;
  adminCount = 1;
});

describe("provisionEntraUser", () => {
  it("raise mode never lowers a role", async () => {
    members.set("u1", "ADMIN");
    await provisionEntraUser({ email: "ann@acme.com", name: "Ann", role: "DEVELOPER", cfg: base });
    expect(members.get("u1")).toBe("ADMIN");
  });

  it("exact mode lowers to what Entra grants, and records it", async () => {
    members.set("u2", "SECURITY");
    await provisionEntraUser({ email: "bob@acme.com", name: "Bob", role: "VIEWER", cfg: { ...base, roleSync: "exact" } });
    expect(members.get("u2")).toBe("VIEWER");
    expect(audit[0]).toMatchObject({ action: "user.role_changed", details: { from: "SECURITY", to: "VIEWER", method: "entra_role_sync" } });
  });

  it("exact mode never demotes the last admin", async () => {
    members.set("u1", "ADMIN");
    await provisionEntraUser({ email: "ann@acme.com", name: "Ann", role: "VIEWER", cfg: { ...base, roleSync: "exact" } });
    expect(members.get("u1")).toBe("ADMIN");
    adminCount = 2;
    await provisionEntraUser({ email: "ann@acme.com", name: "Ann", role: "VIEWER", cfg: { ...base, roleSync: "exact" } });
    expect(members.get("u1")).toBe("VIEWER");
  });
});
