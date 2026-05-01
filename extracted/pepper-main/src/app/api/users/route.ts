import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import bcrypt from "bcryptjs";
import { z } from "zod";

export async function GET(req: NextRequest) {
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
  email: z.string().email(),
  name: z.string().optional(),
  role: z
    .enum(["ADMIN", "SECURITY", "DEVELOPER", "VIEWER"])
    .default("DEVELOPER"),
  password: z.string().min(8).optional(),
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

    // Find or create user
    let user = await prisma.user.findUnique({ where: { email: data.email } });

    if (!user) {
      const passwordHash = data.password
        ? await bcrypt.hash(data.password, 12)
        : await bcrypt.hash(crypto.randomUUID(), 12);

      user = await prisma.user.create({
        data: {
          email: data.email,
          name: data.name,
          passwordHash,
        },
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
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to invite user" },
      { status: 500 },
    );
  }
}
