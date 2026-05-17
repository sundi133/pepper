import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { scanQueue, ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { execFileSync } from "child_process";

function resolveGitDefaultBranch(repoUrl: string) {
  try {
    const output = execFileSync("git", ["ls-remote", "--symref", repoUrl, "HEAD"], {
      encoding: "utf8",
      timeout: 30000,
      windowsHide: process.platform === "win32",
    });
    const match = output.match(/^ref:\s+refs\/heads\/(.+)\s+HEAD/m);
    return match?.[1];
  } catch {
    return undefined;
  }
}

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

  const originalScan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    include: {
      project: {
        include: {
          buildGate: true,
        },
      },
    },
  });

  if (!originalScan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  if (!originalScan.sourceRef) {
    return NextResponse.json(
      { error: "Original scan source is not available for rescan" },
      { status: 409 },
    );
  }

  const projectId = originalScan.projectId;
  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
  });
  const sourceType =
    originalScan.sourceType === "WEBHOOK" ? "GIT_CLONE" : originalScan.sourceType;
  const branch =
    sourceType === "GIT_CLONE"
      ? resolveGitDefaultBranch(originalScan.sourceRef) ||
        originalScan.branch ||
        undefined
      : originalScan.branch || undefined;

  const { removeAllScansForProject } = await import("@/lib/remove-project-scans");
  await removeAllScansForProject(projectId);

  const scan = await prisma.scan.create({
    data: {
      projectId: originalScan.projectId,
      scanType: originalScan.scanType,
      branch,
      baseSha: originalScan.baseSha,
      sourceType,
      sourceRef: originalScan.sourceRef,
      triggeredBy: auth.session.user.id,
      status: "QUEUED",
    },
  });

  const useOrgGithubToken =
    sourceType === "GIT_CLONE" && originalScan.project.connectedViaGithub;

  const jobData: ScanJobData = {
    scanId: scan.id,
    projectId: scan.projectId,
    sourceType: sourceType as ScanJobData["sourceType"],
    sourceRef: originalScan.sourceRef,
    scanType: originalScan.scanType as ScanJobData["scanType"],
    baseSha: originalScan.baseSha || undefined,
    repoUrl: sourceType === "GIT_CLONE" ? originalScan.sourceRef : undefined,
    repoUrlDisplay:
      sourceType === "GIT_CLONE" ? originalScan.sourceRef : undefined,
    useOrgGithubToken,
    svnUrl: sourceType === "SVN_CHECKOUT" ? originalScan.sourceRef : undefined,
    branch,
    orgSettings: buildOrgSettingsForJob(orgSettings, orgId),
    dastTargetUrl: originalScan.project.dastTargetUrl || undefined,
    buildGate: originalScan.project.buildGate
      ? {
          maxCritical: originalScan.project.buildGate.maxCritical,
          maxHigh: originalScan.project.buildGate.maxHigh,
          maxMedium: originalScan.project.buildGate.maxMedium,
          maxLow: originalScan.project.buildGate.maxLow,
          failOnNew: originalScan.project.buildGate.failOnNew,
        }
      : undefined,
  };

  const job = await scanQueue.add("scan", jobData, {
    jobId: scan.id,
  });

  await prisma.scan.update({
    where: { id: scan.id },
    data: { jobId: job.id },
  });

  try {
    const { createScanQueuedNotification } = await import(
      "@/lib/scan-notifications"
    );
    await createScanQueuedNotification({
      userId: auth.session.user.id,
      organizationId: orgId,
      scanId: scan.id,
      projectName: originalScan.project.name,
    });
  } catch (e) {
    console.error("Failed to record notification:", e);
  }

  return NextResponse.json(
    { scanId: scan.id, status: "QUEUED" },
    { status: 201 },
  );
}
