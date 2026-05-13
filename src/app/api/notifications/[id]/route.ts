import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { z } from "zod";

const patchSchema = z.object({
  read: z.boolean().optional(),
});

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { id } = await params;
  const body = await req.json().catch(() => ({}));
  let data: z.infer<typeof patchSchema>;
  try {
    data = patchSchema.parse(body);
  } catch (e) {
    if (e instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: e.issues },
        { status: 400 },
      );
    }
    throw e;
  }

  if (typeof data.read !== "boolean") {
    return NextResponse.json(
      { error: "Body must include read (boolean)" },
      { status: 400 },
    );
  }

  const existing = await prisma.notification.findFirst({
    where: {
      id,
      userId: auth.session.user.id,
      organizationId: orgId,
    },
  });

  if (!existing) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const updated = await prisma.notification.update({
    where: { id },
    data: {
      ...(typeof data.read === "boolean" ? { read: data.read } : {}),
    },
    select: {
      id: true,
      read: true,
      title: true,
      body: true,
      scanId: true,
      createdAt: true,
    },
  });

  return NextResponse.json(updated);
}

export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { id } = await params;

  const result = await prisma.notification.deleteMany({
    where: {
      id,
      userId: auth.session.user.id,
      organizationId: orgId,
    },
  });

  if (result.count === 0) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  return NextResponse.json({ ok: true });
}
