import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { scanQueue, ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";

export async function POST(
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
      project: { include: { buildGate: true } },
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  if (scan.status !== "PAUSED" && scan.status !== "STOPPED") {
    return NextResponse.json(
      { error: "Only paused or stopped scans can be resumed" },
      { status: 400 },
    );
  }

  if (scan.status === "STOPPED") {
    if (!scan.sourceRef) {
      return NextResponse.json(
        { error: "Original scan source is not available for resume" },
        { status: 409 },
      );
    }

    const orgSettings = await prisma.orgSettings.findUnique({
      where: { organizationId: orgId },
    });
    const sourceType =
      scan.sourceType === "WEBHOOK" ? "GIT_CLONE" : scan.sourceType;
    const jobData: ScanJobData = {
      scanId: scan.id,
      projectId: scan.projectId,
      sourceType: sourceType as ScanJobData["sourceType"],
      sourceRef: scan.sourceRef,
      scanType: scan.scanType as ScanJobData["scanType"],
      baseSha: scan.baseSha || undefined,
      commitSha: scan.commitSha || undefined,
      prNumber: scan.prNumber ?? undefined,
      repoUrl: sourceType === "GIT_CLONE" ? scan.sourceRef : undefined,
      svnUrl: sourceType === "SVN_CHECKOUT" ? scan.sourceRef : undefined,
      branch: scan.branch || undefined,
      useOrgGithubToken: scan.project.connectedViaGithub,
      useOrgBitbucketToken: scan.project.connectedViaBitbucket,
      useOrgAzureDevOpsToken: scan.project.connectedViaAzure,
      orgSettings: buildOrgSettingsForJob(orgSettings, orgId),
      dastTargetUrl: scan.project.dastTargetUrl || undefined,
      buildGate: scan.project.buildGate
        ? {
            maxCritical: scan.project.buildGate.maxCritical,
            maxHigh: scan.project.buildGate.maxHigh,
            maxMedium: scan.project.buildGate.maxMedium,
            maxLow: scan.project.buildGate.maxLow,
            failOnNew: scan.project.buildGate.failOnNew,
          }
        : undefined,
    };

    await prisma.$transaction([
      prisma.finding.deleteMany({ where: { scanId } }),
      prisma.scanArtifact.deleteMany({ where: { scanId } }),
      prisma.scan.update({
        where: { id: scanId },
        data: {
          status: "QUEUED",
          startedAt: null,
          completedAt: null,
          errorMessage: null,
          gateResult: "PENDING",
          criticalCount: 0,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
          infoCount: 0,
          filesScanned: 0,
          depsScanned: 0,
          scannerProgress: {},
        },
      }),
    ]);

    const job = await scanQueue.add("scan", jobData, {
      jobId: `${scan.id}:resume:${Date.now()}`,
    });
    await prisma.scan.update({
      where: { id: scanId },
      data: { jobId: job.id },
    });

    try {
      const { createScanQueuedNotification } = await import(
        "@/lib/scan-notifications"
      );
      await createScanQueuedNotification({
        userId: auth.session.user.id,
        organizationId: orgId,
        scanId,
        projectName: scan.project.name,
      });
    } catch (e) {
      console.error("Failed to record notification:", e);
    }

    return NextResponse.json({ scanId, status: "QUEUED" });
  }

  await prisma.scan.update({
    where: { id: scanId },
    data: { status: "RUNNING" },
  });

  try {
    const { notifyScanLifecycleFromApi } = await import("@/lib/scan-notifications");
    await notifyScanLifecycleFromApi({
      scanId,
      organizationId: orgId,
      actorUserId: auth.session.user.id,
      type: "SCAN_RESUMED",
    });
  } catch (e) {
    console.error("Failed to record notification:", e);
  }

  return NextResponse.json({ scanId, status: "RUNNING" });
}
