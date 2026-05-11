import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { z } from "zod";

const updateSchema = z.object({
  projectId: z.string(),
  maxCritical: z.number().int().min(-1),
  maxHigh: z.number().int().min(-1),
  maxMedium: z.number().int().min(-1),
  maxLow: z.number().int().min(-1),
  failOnNew: z.boolean(),
});

export async function PUT(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  try {
    const body = await req.json();
    const data = updateSchema.parse(body);

    const project = await prisma.project.findFirst({
      where: { id: data.projectId, organizationId: orgId },
      select: { id: true },
    });

    if (!project) {
      return NextResponse.json({ error: "Project not found" }, { status: 404 });
    }

    const buildGate = await prisma.buildGate.upsert({
      where: { projectId: data.projectId },
      update: {
        maxCritical: data.maxCritical,
        maxHigh: data.maxHigh,
        maxMedium: data.maxMedium,
        maxLow: data.maxLow,
        failOnNew: data.failOnNew,
      },
      create: {
        projectId: data.projectId,
        maxCritical: data.maxCritical,
        maxHigh: data.maxHigh,
        maxMedium: data.maxMedium,
        maxLow: data.maxLow,
        failOnNew: data.failOnNew,
      },
    });

    return NextResponse.json(buildGate);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to update build gate" },
      { status: 500 },
    );
  }
}
