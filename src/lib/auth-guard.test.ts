import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Session } from "next-auth";

// getActiveOrgId reads the active_org cookie via next/headers; mock the store.
const cookieGet = vi.fn();
vi.mock("next/headers", () => ({
  cookies: vi.fn(async () => ({ get: cookieGet })),
  headers: vi.fn(async () => ({ get: () => null })),
}));
// Neutralise heavy module-level imports unrelated to getActiveOrgId.
vi.mock("@/lib/auth", () => ({ authOptions: {} }));
vi.mock("@/lib/prisma", () => ({ prisma: {} }));

import { getActiveOrgId, getDefaultOrgId, ACTIVE_ORG_COOKIE } from "./auth-guard";

function sessionWith(orgIds: string[]): Session {
  return {
    user: {
      id: "u1",
      memberships: orgIds.map((organizationId) => ({
        organizationId,
        role: "ADMIN" as const,
      })),
    },
    expires: "",
  } as Session;
}

beforeEach(() => {
  vi.clearAllMocks();
  cookieGet.mockReturnValue(undefined);
});

describe("getActiveOrgId", () => {
  it("honours a valid active_org cookie naming an org the user belongs to", async () => {
    const session = sessionWith(["org-a", "org-b"]);
    cookieGet.mockReturnValue({ value: "org-b" });

    const orgId = await getActiveOrgId(session);

    expect(orgId).toBe("org-b");
    expect(cookieGet).toHaveBeenCalledWith(ACTIVE_ORG_COOKIE);
  });

  it("rejects a cookie naming an org the user is NOT a member of and falls back to the default", async () => {
    const session = sessionWith(["org-a", "org-b"]);
    cookieGet.mockReturnValue({ value: "org-evil" });

    const orgId = await getActiveOrgId(session);

    // Must not trust the forged cookie (IDOR) — falls back to memberships[0].
    expect(orgId).toBe("org-a");
    expect(orgId).toBe(getDefaultOrgId(session));
  });

  it("defaults to memberships[0] when the cookie is unset", async () => {
    const session = sessionWith(["org-a", "org-b"]);
    cookieGet.mockReturnValue(undefined);

    const orgId = await getActiveOrgId(session);

    expect(orgId).toBe("org-a");
  });

  it("falls back to the default when no request cookie store is available", async () => {
    const { cookies } = await import("next/headers");
    (cookies as unknown as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("no request scope"),
    );
    const session = sessionWith(["org-a", "org-b"]);

    const orgId = await getActiveOrgId(session);

    expect(orgId).toBe("org-a");
  });

  it("is unaffected for single-org users (cookie ignored unless it matches)", async () => {
    const session = sessionWith(["only-org"]);
    cookieGet.mockReturnValue({ value: "another-org" });

    expect(await getActiveOrgId(session)).toBe("only-org");
  });

  it("returns null when the user has no memberships", async () => {
    expect(await getActiveOrgId(sessionWith([]))).toBeNull();
    expect(await getActiveOrgId(null)).toBeNull();
  });
});
