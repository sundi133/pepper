import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { z } from "zod";

const createProjectSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().optional(),
  repoUrl: z.string().url().optional().or(z.literal("")),
  defaultBranch: z.string().default("main"),
});

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const projects = await prisma.project.findMany({
    where: { organizationId: orgId },
    include: {
      _count: { select: { scans: true } },
      buildGate: true,
      scans: {
        orderBy: { createdAt: "desc" },
        take: 1,
        select: {
          id: true,
          status: true,
          gateResult: true,
          createdAt: true,
          criticalCount: true,
          highCount: true,
        },
      },
    },
    orderBy: { updatedAt: "desc" },
  });

  return NextResponse.json({ projects });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  try {
    const body = await req.json();
    const data = createProjectSchema.parse(body);

    const project = await prisma.project.create({
      data: {
        name: data.name,
        description: data.description,
        repoUrl: data.repoUrl || null,
        defaultBranch: data.defaultBranch,
        organizationId: orgId,
      },
    });

    // Create default build gate
    await prisma.buildGate.create({
      data: {
        projectId: project.id,
        maxCritical: 0,
        maxHigh: 5,
        maxMedium: 20,
        maxLow: -1,
      },
    });

    return NextResponse.json(project, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to create project" },
      { status: 500 },
    );
  }
}
