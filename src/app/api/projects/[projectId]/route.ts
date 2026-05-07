import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { scanQueue } from "@/lib/queue";
import { deleteObject } from "@/lib/minio";
import { z } from "zod";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { projectId } = await params;

  const project = await prisma.project.findFirst({
    where: { id: projectId, organizationId: orgId },
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

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { projectId } = await params;

  try {
    const body = await req.json();
    const data = updateProjectSchema.parse(body);

    const existingProject = await prisma.project.findFirst({
      where: { id: projectId, organizationId: orgId },
      select: { id: true },
    });

    if (!existingProject) {
      return NextResponse.json({ error: "Project not found" }, { status: 404 });
    }

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
  _req: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { projectId } = await params;

  const project = await prisma.project.findFirst({
    where: { id: projectId, organizationId: orgId },
    select: {
      id: true,
      scans: {
        select: {
          id: true,
          status: true,
          jobId: true,
          artifacts: { select: { objectKey: true } },
        },
      },
    },
  });

  if (!project) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  if (
    project.scans.some(
      (scan) => scan.status === "RUNNING" || scan.status === "PAUSED",
    )
  ) {
    return NextResponse.json(
      { error: "Cancel active scans before deleting this project" },
      { status: 409 },
    );
  }

  for (const scan of project.scans) {
    if (!scan.jobId) continue;
    try {
      const job = await scanQueue.getJob(scan.jobId);
      if (job) await job.remove();
    } catch {
      // The queue entry may already be gone or locked by a worker.
    }
  }

  const objectKeys = project.scans.flatMap((scan) =>
    scan.artifacts.map((artifact) => artifact.objectKey),
  );

  await prisma.$transaction([
    prisma.scanArtifact.deleteMany({ where: { scan: { projectId } } }),
    prisma.finding.deleteMany({ where: { scan: { projectId } } }),
    prisma.scan.deleteMany({ where: { projectId } }),
    prisma.buildGate.deleteMany({ where: { projectId } }),
    prisma.scanSchedule.deleteMany({ where: { projectId } }),
    prisma.project.delete({ where: { id: projectId } }),
  ]);

  await Promise.allSettled(objectKeys.map((key) => deleteObject(key)));

  return NextResponse.json({ success: true });
}
