import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ ruleId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const { ruleId } = await params;

  const existing = await prisma.suppressionRule.findFirst({
    where: { id: ruleId, organizationId: orgId },
  });
  if (!existing) {
    return NextResponse.json({ error: "Rule not found" }, { status: 404 });
  }

  try {
    const body = await req.json();
    const rule = await prisma.suppressionRule.update({
      where: { id: ruleId },
      data: {
        enabled: typeof body.enabled === "boolean" ? body.enabled : undefined,
        reason: typeof body.reason === "string" ? body.reason : undefined,
      },
    });
    return NextResponse.json(rule);
  } catch {
    return NextResponse.json(
      { error: "Failed to update rule" },
      { status: 500 },
    );
  }
}

export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ ruleId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const { ruleId } = await params;

  const existing = await prisma.suppressionRule.findFirst({
    where: { id: ruleId, organizationId: orgId },
  });
  if (!existing) {
    return NextResponse.json({ error: "Rule not found" }, { status: 404 });
  }

  await prisma.suppressionRule.delete({ where: { id: ruleId } });
  return NextResponse.json({ success: true });
}
