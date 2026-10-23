import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const requireAuth = vi.fn();
vi.mock("@/lib/auth-guard", () => ({
  requireAuth: (...a: unknown[]) => requireAuth(...a),
  ACTIVE_ORG_COOKIE: "active_org",
}));

import { POST } from "./route";

async function post(body: unknown) {
  // The handler always returns a response; the `| undefined` in its inferred
  // type is a NextResponse-overload quirk, so assert it here.
  const res = await POST(
    new NextRequest("http://localhost/api/org/active", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  );
  return res!;
}

const memberSession = {
  session: {
    user: {
      id: "u1",
      memberships: [
        { organizationId: "org-a", role: "ADMIN" },
        { organizationId: "org-b", role: "DEVELOPER" },
      ],
    },
  },
};

beforeEach(() => {
  vi.clearAllMocks();
  requireAuth.mockResolvedValue(memberSession);
});

describe("POST /api/org/active", () => {
  it("sets the active_org cookie for an org the user belongs to", async () => {
    const res = await post({ organizationId: "org-b" });

    expect(res.status).toBe(200);
    const cookie = res.cookies.get("active_org");
    expect(cookie?.value).toBe("org-b");
    expect(cookie?.httpOnly).toBe(true);
    expect(cookie?.sameSite).toBe("lax");
    expect(cookie?.path).toBe("/");
  });

  it("returns 403 and sets no cookie when the user is not a member", async () => {
    const res = await post({ organizationId: "org-evil" });

    expect(res.status).toBe(403);
    expect(res.cookies.get("active_org")).toBeUndefined();
  });

  it("returns 400 for an invalid body", async () => {
    const res = await post({ nope: true });
    expect(res.status).toBe(400);
  });

  it("returns the auth error when unauthenticated", async () => {
    const { NextResponse } = await import("next/server");
    requireAuth.mockResolvedValue({
      error: NextResponse.json({ error: "Unauthorized" }, { status: 401 }),
    });

    const res = await post({ organizationId: "org-a" });
    expect(res.status).toBe(401);
  });
});
