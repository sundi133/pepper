import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth-guard";
import { computeNextRun } from "@/lib/schedule-utils";
import { z } from "zod";

const scheduleSchema = z.object({
  enabled: z.boolean(),
  frequency: z.enum(["DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "CUSTOM"]),
  cronExpr: z.string().optional(),
  scanType: z
    .enum([
      "FULL",
      "SAST_ONLY",
      "SCA_ONLY",
      "SECRETS_ONLY",
      "IAC_ONLY",
      "ZERO_DAY_ONLY",
      "CONTAINER_ONLY",
      "DAST_ONLY",
    ])
    .default("FULL"),
  branch: z.string().optional(),
});

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { projectId } = await params;

  const schedule = await prisma.scanSchedule.findUnique({
    where: { projectId },
  });

  return NextResponse.json(schedule);
}

export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { projectId } = await params;

  try {
    const body = await req.json();
    const data = scheduleSchema.parse(body);

    const nextRunAt = data.enabled ? computeNextRun(data.frequency) : null;

    const schedule = await prisma.scanSchedule.upsert({
      where: { projectId },
      update: {
        ...data,
        nextRunAt,
      },
      create: {
        projectId,
        ...data,
        nextRunAt,
      },
    });

    return NextResponse.json(schedule);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to update schedule" },
      { status: 500 },
    );
  }
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { projectId } = await params;

  await prisma.scanSchedule.deleteMany({ where: { projectId } });

  return NextResponse.json({ success: true });
}
