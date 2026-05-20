import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { scanQueue, ScanJobData } from "@/lib/queue";
import { uploadObject, ensureBucket } from "@/lib/minio";
import { z } from "zod";
import { withGitCredentials } from "@/lib/git-repo-url";
import { parseGithubRepo } from "@/lib/github-source-link";
import { getOrgGithubAccessToken } from "@/lib/github-connection";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import {
  projectNameFromGitUrl,
  projectNameFromSvnUrl,
  projectNameFromUploadFilename,
} from "@/lib/project-name-from-source";
import { API_CREATE_SCAN_TYPES } from "@/lib/scan-types";

const createScanSchema = z
  .object({
    projectId: z.string().optional(),
    /** When `projectId` is omitted, overrides inferred name from URL or file. */
    newProjectName: z.string().max(100).optional(),
    scanType: z.enum(API_CREATE_SCAN_TYPES).default("FULL"),
    branch: z.string().optional(),
    commitSha: z.string().optional(),
    baseSha: z.string().optional(),
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

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  try {
    const contentType = req.headers.get("content-type") || "";
    let scanParams: z.infer<typeof createScanSchema>;
    let fileBuffer: Buffer | null = null;
    let originalFileName: string | null = null;

    if (contentType.includes("multipart/form-data")) {
      const formData = await req.formData();
      const file = formData.get("file") as File | null;
      const data = formData.get("data") as string | null;

      scanParams = createScanSchema.parse(JSON.parse(data || "{}"));

      if (file) {
        const arrayBuffer = await file.arrayBuffer();
        fileBuffer = Buffer.from(arrayBuffer);
        originalFileName = file.name;
      }
    } else {
      const body = await req.json();
      scanParams = createScanSchema.parse(body);
    }

    const orgId = getDefaultOrgId(auth.session);
    if (!orgId) {
      return NextResponse.json({ error: "No organization" }, { status: 403 });
    }

    if (!fileBuffer && !scanParams.repoUrl && !scanParams.svnUrl) {
      return NextResponse.json(
        { error: "Provide a repository URL, SVN URL, or upload a source archive" },
        { status: 400 },
      );
    }

    const requestedProjectId = scanParams.projectId?.trim();
    let effectiveProjectId = requestedProjectId;

    if (!effectiveProjectId) {
      const nameOverride = scanParams.newProjectName?.trim();
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
        return NextResponse.json(
          {
            error:
              "Select an existing project or provide a repository URL, SVN URL, or upload",
          },
          { status: 400 },
        );
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
      return NextResponse.json({ error: "Project not found" }, { status: 404 });
    }

    const { removeAllScansForProject } = await import("@/lib/remove-project-scans");
    await removeAllScansForProject(effectiveProjectId);

    // Get org settings
    const orgSettings = await prisma.orgSettings.findUnique({
      where: { organizationId: project.organizationId },
    });

    // Create scan record
    const scan = await prisma.scan.create({
      data: {
        projectId: effectiveProjectId,
        scanType: scanParams.scanType,
        branch: scanParams.branch,
        commitSha: scanParams.commitSha,
        baseSha: scanParams.baseSha,
        sourceType: fileBuffer
          ? "UPLOAD"
          : scanParams.repoUrl
            ? "GIT_CLONE"
            : scanParams.svnUrl
              ? "SVN_CHECKOUT"
              : "UPLOAD",
        triggeredBy: auth.session.user.id,
        status: "QUEUED",
      },
    });

    // Upload source file to MinIO if provided
    let sourceRef = "";
    if (fileBuffer) {
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
      scanType: scanParams.scanType,
      baseSha: scanParams.baseSha,
      commitSha: scanParams.commitSha,
      repoUrl: cloneRepoUrl,
      repoUrlDisplay: scanParams.repoUrl,
      svnUrl: scanParams.svnUrl,
      svnRevision: scanParams.svnRevision,
      svnUsername: scanParams.svnUsername,
      svnPassword: scanParams.svnPassword,
      branch: scanParams.branch,
      useOrgGithubToken: useOAuthClone,
      orgSettings: buildOrgSettingsForJob(orgSettings, project.organizationId),
      dastTargetUrl: project.dastTargetUrl || undefined,
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
        projectName: project.name,
      });
    } catch (e) {
      console.error("Failed to record notification:", e);
    }

    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "scan.queued",
      resource: "scan",
      resourceId: scan.id,
      details: { scanType: scanParams.scanType, sourceType: jobData.sourceType },
      ipAddress: ipFromHeaders(req.headers),
    });

    return NextResponse.json(
      { scanId: scan.id, projectId: effectiveProjectId, status: "QUEUED" },
      { status: 201 },
    );
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    console.error("Failed to create scan:", error);
    return NextResponse.json(
      { error: "Failed to create scan" },
      { status: 500 },
    );
  }
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { searchParams } = new URL(req.url);
  const projectId = searchParams.get("projectId");
  const status = searchParams.get("status");
  const page = parseInt(searchParams.get("page") || "1");
  const limit = parseInt(searchParams.get("limit") || "20");

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const where: Record<string, unknown> = {
    project: { organizationId: orgId },
  };
  if (projectId) where.projectId = projectId;
  if (status) where.status = status;

  const [scans, total] = await Promise.all([
    prisma.scan.findMany({
      where,
      include: { project: { select: { name: true } } },
      orderBy: { createdAt: "desc" },
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.scan.count({ where }),
  ]);

  return NextResponse.json({
    scans,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}
