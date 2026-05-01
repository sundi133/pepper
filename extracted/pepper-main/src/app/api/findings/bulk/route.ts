import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth-guard";
import { z } from "zod";

const bulkUpdateSchema = z.object({
  findingIds: z.array(z.string()).min(1).max(500),
  status: z.enum([
    "OPEN",
    "IN_PROGRESS",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "RESOLVED",
  ]),
  statusNote: z.string().optional(),
});

export async function PATCH(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  try {
    const body = await req.json();
    const data = bulkUpdateSchema.parse(body);

    const result = await prisma.finding.updateMany({
      where: { id: { in: data.findingIds } },
      data: {
        status: data.status,
        statusNote: data.statusNote || null,
        statusUpdatedBy: auth.session.user.id,
        statusUpdatedAt: new Date(),
      },
    });

    return NextResponse.json({
      updated: result.count,
      status: data.status,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to update findings" },
      { status: 500 },
    );
  }
}
