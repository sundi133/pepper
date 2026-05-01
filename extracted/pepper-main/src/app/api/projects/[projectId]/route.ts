import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth-guard";
import { z } from "zod";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { projectId } = await params;

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    include: {
      buildGate: true,
      _count: { select: { scans: true } },
      scans: {
        orderBy: { createdAt: "desc" },
        take: 10,
        select: {
          id: true,
          status: true,
          scanType: true,
          branch: true,
          gateResult: true,
          createdAt: true,
          completedAt: true,
          criticalCount: true,
          highCount: true,
          mediumCount: true,
          lowCount: true,
          infoCount: true,
          filesScanned: true,
        },
      },
    },
  });

  if (!project) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  return NextResponse.json(project);
}

const updateProjectSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  description: z.string().optional(),
  repoUrl: z.string().url().optional().or(z.literal("")),
  defaultBranch: z.string().optional(),
});

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { projectId } = await params;

  try {
    const body = await req.json();
    const data = updateProjectSchema.parse(body);

    const project = await prisma.project.update({
      where: { id: projectId },
      data,
    });

    return NextResponse.json(project);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to update project" },
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

  await prisma.project.delete({ where: { id: projectId } });

  return NextResponse.json({ success: true });
}
