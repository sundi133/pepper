import bcrypt from "bcryptjs";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const audit: Array<Record<string, unknown>> = [];
const users = new Map<string, { id: string; email: string; name: string | null; passwordHash: string | null }>();

vi.mock("@/lib/prisma", () => ({
  prisma: {
    user: { findUnique: vi.fn(async ({ where }: { where: { email?: string } }) => (where.email ? (users.get(where.email) ?? null) : null)) },
    orgMember: {
      findMany: vi.fn(async ({ where }: { where: { userId: string } }) =>
        where.userId === "u1" ? [{ organizationId: "orgA" }, { organizationId: "orgB" }] : [],
      ),
    },
    auditLog: { create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => audit.push(data)) },
  },
}));
vi.mock("@auth/prisma-adapter", () => ({ PrismaAdapter: () => ({}) }));

import { authOptions } from "./auth";

type Authorize = (c: Record<string, string>, req: { headers: Record<string, string> }) => Promise<unknown>;
const authorize = (authOptions.providers[0] as unknown as { options: { authorize: Authorize } }).options.authorize;
const req = { headers: { "x-forwarded-for": "203.0.113.7, 10.0.0.1" } };

beforeAll(async () => {
  users.set("ann@acme.test", { id: "u1", email: "ann@acme.test", name: "Ann", passwordHash: await bcrypt.hash("correct horse", 4) });
});
beforeEach(() => {
  audit.length = 0;
});

describe("sign-in auditing", () => {
  it("records a successful password login in each of the user's organizations", async () => {
    await expect(authorize({ email: "ann@acme.test", password: "correct horse" }, req)).resolves.toMatchObject({ id: "u1" });
    expect(audit).toHaveLength(2);
    expect(audit.map((a) => a.organizationId)).toEqual(["orgA", "orgB"]);
    expect(audit[0]).toMatchObject({ action: "user.login", userId: "u1", ipAddress: "203.0.113.7", details: { method: "password" } });
  });

  it("records a wrong password without the password", async () => {
    await expect(authorize({ email: "ann@acme.test", password: "guess" }, req)).resolves.toBeNull();
    expect(audit[0]).toMatchObject({ action: "user.login_failed", userId: "u1", details: { reason: "wrong_password", email: "ann@acme.test" } });
    expect(JSON.stringify(audit)).not.toContain("guess");
  });

  it("records unknown accounts instance-wide", async () => {
    await expect(authorize({ email: "nobody@acme.test", password: "x" }, req)).resolves.toBeNull();
    expect(audit).toEqual([
      expect.objectContaining({ organizationId: null, userId: null, action: "user.login_failed", details: expect.objectContaining({ reason: "unknown_user" }) }),
    ]);
  });

  it("records logouts", async () => {
    await authOptions.events!.signOut!({ token: { userId: "u1" }, session: undefined as never } as never);
    expect(audit.map((a) => [a.organizationId, a.action])).toEqual([["orgA", "user.logout"], ["orgB", "user.logout"]]);
  });
});
