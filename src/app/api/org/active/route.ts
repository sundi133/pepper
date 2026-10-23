import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { requireAuth, ACTIVE_ORG_COOKIE } from "@/lib/auth-guard";

const bodySchema = z.object({ organizationId: z.string().min(1) });

/**
 * Select the active organisation for a multi-org user.
 *
 * This is deliberately NOT role-gated: any member of the target org may make it
 * their active org (switching is not itself a privileged action — every route
 * still applies its own role checks against the resolved org). It is, however,
 * membership-gated: setting the cookie to an org the caller does not belong to
 * is refused with 403, so the switcher can never be used to reach another org.
 */
export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  let organizationId: string;
  try {
    const parsed = bodySchema.parse(await req.json());
    organizationId = parsed.organizationId;
  } catch {
    return NextResponse.json({ error: "Invalid input" }, { status: 400 });
  }

  const isMember = auth.session.user.memberships?.some(
    (m) => m.organizationId === organizationId,
  );
  if (!isMember) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const res = NextResponse.json({ success: true, organizationId });
  res.cookies.set({
    name: ACTIVE_ORG_COOKIE,
    value: organizationId,
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    secure: process.env.NODE_ENV === "production",
  });
  return res;
}
