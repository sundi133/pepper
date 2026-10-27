import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requireAuth, getActiveOrgId } from "@/lib/auth-guard";

const prefsSchema = z
  .object({
    emailOnScanComplete: z.boolean(),
    emailOnGateFail: z.boolean(),
    emailOnCritical: z.boolean(),
  })
  .partial();

const SELECT = {
  emailOnScanComplete: true,
  emailOnGateFail: true,
  emailOnCritical: true,
} as const;

/** The caller's email preferences in the active organization. */
export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const member = await prisma.orgMember.findUnique({
    where: { userId_organizationId: { userId: auth.session.user.id, organizationId: orgId } },
    select: SELECT,
  });
  if (!member) return NextResponse.json({ error: "Not a member" }, { status: 404 });
  return NextResponse.json(member);
}

export async function PUT(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const parsed = prefsSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid preferences" }, { status: 400 });
  }
  const where = {
    userId_organizationId: { userId: auth.session.user.id, organizationId: orgId },
  };
  if (!(await prisma.orgMember.findUnique({ where, select: { id: true } }))) {
    return NextResponse.json({ error: "Not a member" }, { status: 404 });
  }
  const updated = await prisma.orgMember.update({ where, data: parsed.data, select: SELECT });
  return NextResponse.json(updated);
}
