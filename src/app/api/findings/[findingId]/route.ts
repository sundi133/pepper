import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth-guard";
import { z } from "zod";

const updateStatusSchema = z.object({
  status: z.enum([
    "OPEN",
    "IN_PROGRESS",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "RESOLVED",
  ]),
  statusNote: z.string().optional(),
});

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ findingId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { findingId } = await params;

  try {
    const body = await req.json();
    const data = updateStatusSchema.parse(body);

    const finding = await prisma.finding.update({
      where: { id: findingId },
      data: {
        status: data.status,
        statusNote: data.statusNote || null,
        statusUpdatedBy: auth.session.user.id,
        statusUpdatedAt: new Date(),
      },
    });

    return NextResponse.json(finding);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to update finding" },
      { status: 500 },
    );
  }
}

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ findingId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { findingId } = await params;

  const finding = await prisma.finding.findUnique({
    where: { id: findingId },
  });

  if (!finding) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  return NextResponse.json(finding);
}
