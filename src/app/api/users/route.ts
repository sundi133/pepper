import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { logger } from "@/lib/logger";

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  const members = await prisma.orgMember.findMany({
    where: { organizationId: orgId },
    include: {
      user: {
        select: {
          id: true,
          name: true,
          email: true,
          image: true,
          createdAt: true,
        },
      },
    },
    orderBy: { createdAt: "asc" },
  });

  return NextResponse.json({ members });
}

const inviteSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  name: z.string().trim().optional(),
  role: z
    .enum(["ADMIN", "SECURITY", "DEVELOPER", "VIEWER"])
    .default("DEVELOPER"),
  password: z.string().min(8, "Password must be at least 8 characters"),
});

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  try {
    const body = await req.json();
    const data = inviteSchema.parse(body);

    let user = await prisma.user.findUnique({ where: { email: data.email } });

    if (!user) {
      const passwordHash = await bcrypt.hash(data.password, 12);

      user = await prisma.user.create({
        data: {
          email: data.email,
          name: data.name || null,
          passwordHash,
        },
      });
    } else if (data.name && !user.name) {
      user = await prisma.user.update({
        where: { id: user.id },
        data: { name: data.name },
      });
    }

    // Add to organization
    const member = await prisma.orgMember.upsert({
      where: {
        userId_organizationId: { userId: user.id, organizationId: orgId },
      },
      update: { role: data.role },
      create: {
        userId: user.id,
        organizationId: orgId,
        role: data.role,
      },
    });

    return NextResponse.json({ member }, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        {
          error: error.issues[0]?.message || "Invalid input",
          details: error.issues,
        },
        { status: 400 },
      );
    }
    logger.error({ error }, "Failed to invite user");
    return NextResponse.json(
      { error: "Failed to invite user" },
      { status: 500 },
    );
  }
}
