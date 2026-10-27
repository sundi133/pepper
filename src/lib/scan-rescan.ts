import { normalizeScanSelection } from "@/lib/scan-types";
import { execFileSync } from "child_process";
import { prisma } from "@/lib/prisma";
import { scanQueue, ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { writeAuditLog } from "@/lib/audit-log";
import { objectExists } from "@/lib/minio";
import { uploadExpiredMessage } from "@/lib/data-retention";

export type ScanActionResult =
  | { ok: true; scanId: string; projectId: string }
  | { ok: false; status: number; error: string };

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

/**
 * Queue a new scan of the same source as an earlier scan (the Rescan button).
 *
 * The caller is responsible for authorization (DEVELOPER or above). The
 * earlier scan stays as history; one still in progress for the repository is
 * stopped first.
 */
export async function rescanScan(params: {
  orgId: string;
  userId: string;
  scanId: string;
  /** Overrides the original scan's type; omitted reuses it. */
  scanType?: ScanJobData["scanType"];
  /** With scanType, the scanner groups to combine; omitted reuses the original's. */
  scanModules?: string[];
  ipAddress?: string | null;
  /** Extra audit detail naming the client that made the change (e.g. "mcp"). */
  via?: string;
}): Promise<ScanActionResult> {
  const { orgId, userId, scanId } = params;

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
    return { ok: false, status: 404, error: "Scan not found" };
  }

  if (!originalScan.sourceRef) {
    return { ok: false, status: 409, error: "Original scan source is not available for rescan" };
  }

  // A retention policy may have deleted the uploaded archive. Check before the
  // old results are removed below, so they aren't lost to a scan that can't run.
  if (
    originalScan.sourceType === "UPLOAD" &&
    originalScan.sourceRef.startsWith("scans/") &&
    (await objectExists(originalScan.sourceRef)) === false
  ) {
    return { ok: false, status: 410, error: uploadExpiredMessage() };
  }

  const projectId = originalScan.projectId;
  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
  });
  const sourceType =
    originalScan.sourceType === "WEBHOOK" ? "GIT_CLONE" : originalScan.sourceType;
  // A new type replaces the whole selection; otherwise keep the original's modules.
  const { scanType, scanModules } = params.scanType
    ? normalizeScanSelection(params.scanType, params.scanModules)
    : { scanType: originalScan.scanType, scanModules: originalScan.scanModules };
  const branch =
    sourceType === "GIT_CLONE"
      ? resolveGitDefaultBranch(originalScan.sourceRef) ||
        originalScan.branch ||
        undefined
      : originalScan.branch || undefined;

  // Earlier scans stay as history; one still in progress is stopped.
  const { cancelActiveScansForProject } = await import("@/lib/active-project-scans");
  try {
    await cancelActiveScansForProject(projectId);
  } catch (err) {
    console.error("Failed to stop the active scan during rescan:", err);
    return {
      ok: false,
      status: 500,
      error: "Failed to prepare the repository for rescan. Please try again.",
    };
  }

  const scan = await prisma.scan.create({
    data: {
      projectId: originalScan.projectId,
      scanType,
      scanModules,
      branch,
      baseSha: originalScan.baseSha,
      sourceType,
      sourceRef: originalScan.sourceRef,
      triggeredBy: userId,
      status: "QUEUED",
    },
  });

  const isGitClone = sourceType === "GIT_CLONE";
  const useOrgGithubToken =
    isGitClone && originalScan.project.connectedViaGithub;
  const useOrgBitbucketToken =
    isGitClone && originalScan.project.connectedViaBitbucket;
  const useOrgAzureDevOpsToken =
    isGitClone && originalScan.project.connectedViaAzure;

  const jobData: ScanJobData = {
    scanId: scan.id,
    projectId: scan.projectId,
    sourceType: sourceType as ScanJobData["sourceType"],
    sourceRef: originalScan.sourceRef,
    scanType: scanType as ScanJobData["scanType"],
    scanModules,
    baseSha: originalScan.baseSha || undefined,
    commitSha: originalScan.commitSha || undefined,
    prNumber: originalScan.prNumber ?? undefined,
    repoUrl: sourceType === "GIT_CLONE" ? originalScan.sourceRef : undefined,
    repoUrlDisplay:
      sourceType === "GIT_CLONE" ? originalScan.sourceRef : undefined,
    useOrgGithubToken,
    useOrgBitbucketToken,
    useOrgAzureDevOpsToken,
    svnUrl: sourceType === "SVN_CHECKOUT" ? originalScan.sourceRef : undefined,
    branch,
    orgSettings: buildOrgSettingsForJob(orgSettings, orgId),
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
      userId,
      organizationId: orgId,
      scanId: scan.id,
      projectName: originalScan.project.name,
    });
  } catch (e) {
    console.error("Failed to record notification:", e);
  }

  await writeAuditLog({
    organizationId: orgId,
    userId,
    action: "scan.rescanned",
    resource: "scan",
    resourceId: scan.id,
    details: {
      previousScanId: scanId,
      projectName: originalScan.project.name,
      scanType,
      branch: branch ?? null,
      ...(params.via ? { via: params.via } : {}),
    },
    ipAddress: params.ipAddress ?? null,
  });

  return { ok: true, scanId: scan.id, projectId: scan.projectId };
}
