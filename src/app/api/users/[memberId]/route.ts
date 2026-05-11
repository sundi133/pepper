import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import {
  requireAuth,
  getDefaultOrgId,
  requireRole,
} from "@/lib/auth-guard";
import { logger } from "@/lib/logger";
import { z } from "zod";

const patchMemberSchema = z.object({
  role: z.enum(["ADMIN", "SECURITY", "DEVELOPER", "VIEWER"]),
});

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ memberId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const roleAuth = await requireRole(orgId, "ADMIN");
  if ("error" in roleAuth) return roleAuth.error;

  const { memberId } = await params;

  try {
    const body = await req.json();
    const { role } = patchMemberSchema.parse(body);

    const target = await prisma.orgMember.findFirst({
      where: { id: memberId, organizationId: orgId },
    });

    if (!target) {
      return NextResponse.json({ error: "Member not found" }, { status: 404 });
    }

    if (target.role === role) {
      return NextResponse.json({ member: target });
    }

    if (target.role === "ADMIN" && role !== "ADMIN") {
      const adminCount = await prisma.orgMember.count({
        where: { organizationId: orgId, role: "ADMIN" },
      });
      if (adminCount <= 1) {
        return NextResponse.json(
          { error: "Cannot demote the last organization admin" },
          { status: 400 },
        );
      }
    }

    const member = await prisma.orgMember.update({
      where: { id: memberId },
      data: { role },
    });

    return NextResponse.json({ member });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: error.issues[0]?.message || "Invalid input" },
        { status: 400 },
      );
    }
    logger.error({ error, memberId, orgId }, "Failed to update member role");
    return NextResponse.json(
      { error: "Failed to update role" },
      { status: 500 },
    );
  }
}

export async function DELETE(
  _req: Request,
  { params }: { params: Promise<{ memberId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const roleAuth = await requireRole(orgId, "ADMIN");
  if ("error" in roleAuth) return roleAuth.error;

  const { memberId } = await params;

  try {
    const target = await prisma.orgMember.findFirst({
      where: { id: memberId, organizationId: orgId },
    });

    if (!target) {
      return NextResponse.json({ error: "Member not found" }, { status: 404 });
    }

    const memberCount = await prisma.orgMember.count({
      where: { organizationId: orgId },
    });
    if (memberCount <= 1) {
      return NextResponse.json(
        { error: "Cannot remove the last organization member" },
        { status: 400 },
      );
    }

    if (target.role === "ADMIN") {
      const adminCount = await prisma.orgMember.count({
        where: { organizationId: orgId, role: "ADMIN" },
      });
      if (adminCount <= 1) {
        return NextResponse.json(
          { error: "Cannot remove the last organization admin" },
          { status: 400 },
        );
      }
    }

    await prisma.orgMember.delete({
      where: { id: memberId },
    });

    return NextResponse.json({ ok: true });
  } catch (error) {
    logger.error({ error, memberId, orgId }, "Failed to remove team member");
    return NextResponse.json(
      { error: "Failed to remove member" },
      { status: 500 },
    );
  }
}
