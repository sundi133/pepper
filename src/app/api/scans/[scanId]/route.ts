import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { scanQueue } from "@/lib/queue";
import { deleteObject } from "@/lib/minio";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { scanId } = await params;

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    include: {
      project: {
        select: {
          id: true,
          name: true,
          organizationId: true,
          repoUrl: true,
          defaultBranch: true,
        },
      },
      artifacts: { select: { type: true, objectKey: true, size: true } },
      _count: { select: { findings: true } },
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  return NextResponse.json(scan);
}

export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { scanId } = await params;

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: {
      id: true,
      status: true,
      jobId: true,
      artifacts: { select: { objectKey: true } },
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  if (scan.status === "RUNNING" || scan.status === "PAUSED") {
    return NextResponse.json(
      { error: "Cancel the active scan before deleting it" },
      { status: 409 },
    );
  }

  if (scan.jobId) {
    try {
      const job = await scanQueue.getJob(scan.jobId);
      if (job) await job.remove();
    } catch {
      // The queue entry may already be gone or locked by a worker.
    }
  }

  const objectKeys = scan.artifacts.map((artifact) => artifact.objectKey);

  await prisma.$transaction([
    prisma.scanArtifact.deleteMany({ where: { scanId } }),
    prisma.finding.deleteMany({ where: { scanId } }),
    prisma.scan.delete({ where: { id: scanId } }),
  ]);

  await Promise.allSettled(objectKeys.map((key) => deleteObject(key)));

  return NextResponse.json({ success: true });
}
