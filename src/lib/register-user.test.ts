import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("@/lib/prisma", () => ({
  prisma: {
    user: { findUnique: vi.fn() },
    $transaction: vi.fn(),
  },
}));

vi.mock("@/lib/org-slug", () => ({
  uniqueOrganizationSlug: vi.fn().mockResolvedValue("acme-security"),
}));

import { prisma } from "@/lib/prisma";
import {
  isPublicRegistrationEnabled,
  registerNewUser,
  RegisterUserError,
} from "./register-user";

describe("register-user", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.ALLOW_PUBLIC_REGISTRATION;
  });

  it("allows registration by default", () => {
    expect(isPublicRegistrationEnabled()).toBe(true);
  });

  it("respects ALLOW_PUBLIC_REGISTRATION=false", () => {
    process.env.ALLOW_PUBLIC_REGISTRATION = "false";
    expect(isPublicRegistrationEnabled()).toBe(false);
  });

  it("rejects duplicate email", async () => {
    vi.mocked(prisma.user.findUnique).mockResolvedValue({ id: "u1" } as never);
    await expect(
      registerNewUser({
        email: "a@example.com",
        password: "password123",
        organizationName: "Acme",
      }),
    ).rejects.toBeInstanceOf(RegisterUserError);
  });
});
