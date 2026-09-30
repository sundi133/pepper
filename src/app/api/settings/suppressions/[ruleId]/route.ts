import { NextRequest, NextResponse } from "next/server";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
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
    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "suppression.updated",
      resource: "suppression",
      resourceId: ruleId,
      details: { enabled: { from: existing.enabled, to: rule.enabled }, reason: rule.reason },
      ipAddress: ipFromHeaders(req.headers),
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

  await prisma.suppressionRule.delete({ where: { id: ruleId } });
  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "suppression.deleted",
    resource: "suppression",
    resourceId: ruleId,
    details: { ruleId: existing.ruleId, cweId: existing.cweId, filePathPattern: existing.filePathPattern, reason: existing.reason },
    ipAddress: ipFromHeaders(req.headers),
  });
  return NextResponse.json({ success: true });
}
