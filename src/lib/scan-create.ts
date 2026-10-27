import { z } from "zod";
import { progressWithScanModules } from "@/lib/scan-progress";
import { prisma } from "@/lib/prisma";
import { scanQueue, ScanJobData } from "@/lib/queue";
import { uploadObject, ensureBucket } from "@/lib/minio";
import { compiledUploadObjectKey, isCompiledArtifactUpload } from "@/lib/compiled-scan/upload";
import { withGitCredentials } from "@/lib/git-repo-url";
import { parseGithubRepo } from "@/lib/github-source-link";
import { getOrgGithubAccessToken } from "@/lib/github-connection";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { writeAuditLog } from "@/lib/audit-log";
import {
  projectNameFromGitUrl,
  projectNameFromSvnUrl,
  projectNameFromUploadFilename,
} from "@/lib/project-name-from-source";
import {
  API_CREATE_SCAN_TYPES,
  SCAN_MODULE_IDS,
  normalizeScanSelection,
  type ScanModuleId,
} from "@/lib/scan-types";
import type { ScanActionResult } from "@/lib/scan-rescan";

/** Strip HTML tags and trim whitespace to prevent stored XSS. */
function sanitizeText(value: string): string {
  return value.replace(/<[^>]*>/g, "").trim();
}

export const createScanSchema = z
  .object({
    projectId: z.string().optional(),
    /** When `projectId` is omitted, overrides inferred name from URL or file. */
    newProjectName: z.string().max(100).transform(sanitizeText).optional(),
    /**
     * CI: reuse the org's project with this exact name (created on first use)
     * so repeated pipeline runs build one project's history instead of a new
     * project per run. Ignored when `projectId` is given.
     */
    projectName: z.string().max(100).transform(sanitizeText).optional(),
    scanType: z.enum(API_CREATE_SCAN_TYPES).default("FULL"),
    /** Combine scanner groups on one scan (e.g. ["SAST","SECRETS"]). */
    scanModules: z.array(z.enum(SCAN_MODULE_IDS as [ScanModuleId, ...ScanModuleId[]])).max(7).optional(),
    branch: z.string().optional(),
    commitSha: z.string().optional(),
    baseSha: z.string().optional(),
    prNumber: z.number().int().positive().optional(),
    repoUrl: z.string().optional(),
    /** Used only for clone; never stored on Scan.sourceRef. */
    repoToken: z.string().optional(),
    svnUrl: z.string().url("Invalid SVN URL").optional(),
    svnRevision: z
      .string()
      .regex(
        /^(\d+|HEAD|\{[\d\-T:]+\})$/i,
        "Revision must be a number, HEAD, or {date}",
      )
      .optional(),
    svnUsername: z.string().optional(),
    svnPassword: z.string().optional(),
  })
  .refine((data) => !(data.repoUrl && data.svnUrl), {
    message: "Cannot specify both repoUrl and svnUrl",
    path: ["svnUrl"],
  });

export type CreateScanParams = z.infer<typeof createScanSchema>;

/**
 * Create a scan (and its repository, when needed) and queue it — the New Scan
 * form and CI's `POST /api/scans`.
 *
 * The caller is responsible for authorization (DEVELOPER or above) and for
 * validating any uploaded archive. Unexpected failures throw.
 */
export async function queueNewScan(params: {
  orgId: string;
  userId: string;
  scanParams: CreateScanParams;
  fileBuffer?: Buffer | null;
  originalFileName?: string | null;
  ipAddress?: string | null;
  /** Extra audit detail naming the client that made the change (e.g. "mcp"). */
  via?: string;
}): Promise<ScanActionResult> {
  const { orgId, scanParams } = params;
  const fileBuffer = params.fileBuffer ?? null;
  const originalFileName = params.originalFileName ?? null;

  if (!fileBuffer && !scanParams.repoUrl && !scanParams.svnUrl) {
    return {
      ok: false,
      status: 400,
      error: "Provide a repository URL, SVN URL, or upload a source archive",
    };
  }

  const requestedProjectId = scanParams.projectId?.trim();
  let effectiveProjectId = requestedProjectId;

  const reuseName = scanParams.projectName?.trim();
  if (!effectiveProjectId && reuseName) {
    const existing = await prisma.project.findFirst({
      where: { organizationId: orgId, name: reuseName },
      orderBy: { createdAt: "asc" },
      select: { id: true },
    });
    if (existing) effectiveProjectId = existing.id;
  }

  if (!effectiveProjectId) {
    const nameOverride = scanParams.newProjectName?.trim() || reuseName;
    let name: string;
    let repoUrl: string | null = null;
    let defaultBranch = scanParams.branch?.trim() || "main";

    if (fileBuffer) {
      name =
        nameOverride ||
        projectNameFromUploadFilename(originalFileName || "source.zip");
      defaultBranch = "main";
    } else if (scanParams.repoUrl?.trim()) {
      const u = scanParams.repoUrl.trim();
      name = nameOverride || projectNameFromGitUrl(u);
      repoUrl = u;
    } else if (scanParams.svnUrl?.trim()) {
      const u = scanParams.svnUrl.trim();
      name = nameOverride || projectNameFromSvnUrl(u);
      defaultBranch = "main";
    } else {
      return {
        ok: false,
        status: 400,
        error:
          "Select an existing project or provide a repository URL, SVN URL, or upload",
      };
    }

    const created = await createProjectWithBuildGate({
      organizationId: orgId,
      name,
      repoUrl,
      defaultBranch,
    });
    effectiveProjectId = created.id;
  }

  // Verify project exists in the caller's organization.
  const project = await prisma.project.findFirst({
    where: { id: effectiveProjectId, organizationId: orgId },
    include: { organization: true, buildGate: true },
  });

  if (!project) {
    return { ok: false, status: 404, error: "Project not found" };
  }

  // Earlier scans stay as history; one still in progress is stopped.
  const { cancelActiveScansForProject } = await import("@/lib/active-project-scans");
  await cancelActiveScansForProject(effectiveProjectId);

  // Get org settings
  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: project.organizationId },
  });

  const selection = normalizeScanSelection(scanParams.scanType, scanParams.scanModules);

  // Create scan record
  const scan = await prisma.scan.create({
    data: {
      projectId: effectiveProjectId,
      scanType: selection.scanType,
      scannerProgress: progressWithScanModules(selection.scanModules),
      branch: scanParams.branch,
      commitSha: scanParams.commitSha,
      baseSha: scanParams.baseSha,
      prNumber: scanParams.prNumber,
      sourceType: fileBuffer
        ? "UPLOAD"
        : scanParams.repoUrl
          ? "GIT_CLONE"
          : scanParams.svnUrl
            ? "SVN_CHECKOUT"
            : "UPLOAD",
      triggeredBy: params.userId,
      status: "QUEUED",
    },
  });

  // Upload source file to MinIO if provided
  let sourceRef = "";
  if (fileBuffer && originalFileName && isCompiledArtifactUpload(originalFileName)) {
    // A single compiled artifact: the worker's compiled-code scan decompiles it.
    await ensureBucket();
    sourceRef = compiledUploadObjectKey(scan.id, originalFileName);
    await uploadObject(sourceRef, fileBuffer, "application/octet-stream");
  } else if (fileBuffer) {
    await ensureBucket();
    const ext =
      originalFileName?.match(/\.(zip|tar\.gz|tgz|tar)$/i)?.[0] || ".zip";
    sourceRef = `scans/${scan.id}/source${ext}`;
    const mimeType = ext === ".zip" ? "application/zip" : "application/x-tar";
    await uploadObject(sourceRef, fileBuffer, mimeType);
  } else if (scanParams.repoUrl) {
    sourceRef = scanParams.repoUrl;
  } else if (scanParams.svnUrl) {
    sourceRef = scanParams.svnUrl;
  }

  // Update scan with sourceRef
  await prisma.scan.update({
    where: { id: scan.id },
    data: { sourceRef },
  });

  const orgGhToken = await getOrgGithubAccessToken(orgId);
  const useOAuthClone = Boolean(
    scanParams.repoUrl?.trim() &&
      parseGithubRepo(scanParams.repoUrl) &&
      orgGhToken &&
      !scanParams.repoToken?.trim(),
  );

  // Enqueue job
  const cloneRepoUrl =
    scanParams.repoUrl && scanParams.repoToken?.trim()
      ? withGitCredentials(scanParams.repoUrl, scanParams.repoToken)
      : scanParams.repoUrl;

  const jobData: ScanJobData = {
    scanId: scan.id,
    projectId: effectiveProjectId,
    sourceType: fileBuffer
      ? "UPLOAD"
      : scanParams.repoUrl
        ? "GIT_CLONE"
        : scanParams.svnUrl
          ? "SVN_CHECKOUT"
          : "UPLOAD",
    sourceRef,
    scanType: selection.scanType,
    scanModules: selection.scanModules,
    baseSha: scanParams.baseSha,
    commitSha: scanParams.commitSha,
    prNumber: scanParams.prNumber,
    repoUrl: cloneRepoUrl,
    repoUrlDisplay: scanParams.repoUrl,
    svnUrl: scanParams.svnUrl,
    svnRevision: scanParams.svnRevision,
    svnUsername: scanParams.svnUsername,
    svnPassword: scanParams.svnPassword,
    branch: scanParams.branch,
    useOrgGithubToken: useOAuthClone,
    orgSettings: buildOrgSettingsForJob(orgSettings, project.organizationId),
    buildGate: project.buildGate
      ? {
          maxCritical: project.buildGate.maxCritical,
          maxHigh: project.buildGate.maxHigh,
          maxMedium: project.buildGate.maxMedium,
          maxLow: project.buildGate.maxLow,
          failOnNew: project.buildGate.failOnNew,
        }
      : undefined,
  };

  let job;
  try {
    job = await scanQueue.add("scan", jobData, {
      jobId: scan.id,
    });
  } catch (queueErr) {
    console.error("Failed to enqueue scan job:", queueErr);
    await prisma.scan.update({
      where: { id: scan.id },
      data: { status: "FAILED" },
    });
    return {
      ok: false,
      status: 503,
      error: "Failed to enqueue scan — queue unavailable",
    };
  }

  await prisma.scan.update({
    where: { id: scan.id },
    data: { jobId: job.id },
  });

  try {
    const { createScanQueuedNotification } = await import(
      "@/lib/scan-notifications"
    );
    await createScanQueuedNotification({
      userId: params.userId,
      organizationId: orgId,
      scanId: scan.id,
      projectName: project.name,
    });
  } catch (e) {
    console.error("Failed to record notification:", e);
  }

  await writeAuditLog({
    organizationId: orgId,
    userId: params.userId,
    action: "scan.queued",
    resource: "scan",
    resourceId: scan.id,
    details: {
      scanType: selection.scanType,
      ...(selection.scanModules.length > 0 && { scanModules: selection.scanModules }),
      sourceType: jobData.sourceType,
      ...(params.via ? { via: params.via } : {}),
    },
    ipAddress: params.ipAddress ?? null,
  });

  return { ok: true, scanId: scan.id, projectId: effectiveProjectId };
}
