import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, requireRole, getDefaultOrgId } from "@/lib/auth-guard";
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
    ])
    .default("FULL"),
  branch: z.string().optional(),
});

/**
 * Resolve the caller's org and confirm the project belongs to it. Without
 * this, any signed-in user could read or change another org's schedules by
 * project id.
 */
async function authorizeProject(
  projectId: string,
  minRole?: "DEVELOPER",
): Promise<{ error: NextResponse } | { ok: true }> {
  const auth = await requireAuth();
  if ("error" in auth) return { error: auth.error as NextResponse };
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return { error: NextResponse.json({ error: "No organization" }, { status: 403 }) };
  }
  if (minRole) {
    const roleAuth = await requireRole(orgId, minRole);
    if ("error" in roleAuth) return { error: roleAuth.error as NextResponse };
  }
  const project = await prisma.project.findFirst({
    where: { id: projectId, organizationId: orgId },
    select: { id: true },
  });
  if (!project) {
    return { error: NextResponse.json({ error: "Project not found" }, { status: 404 }) };
  }
  return { ok: true };
}

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const { projectId } = await params;
  const access = await authorizeProject(projectId);
  if ("error" in access) return access.error;

  const schedule = await prisma.scanSchedule.findUnique({
    where: { projectId },
  });

  return NextResponse.json(schedule);
}

export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const { projectId } = await params;
  const access = await authorizeProject(projectId, "DEVELOPER");
  if ("error" in access) return access.error;

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
  const { projectId } = await params;
  const access = await authorizeProject(projectId, "DEVELOPER");
  if ("error" in access) return access.error;

  await prisma.scanSchedule.deleteMany({ where: { projectId } });

  return NextResponse.json({ success: true });
}
