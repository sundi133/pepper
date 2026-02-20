import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { scanQueue, ScanJobData } from "@/lib/queue";
import { uploadObject, ensureBucket } from "@/lib/minio";
import { z } from "zod";

const createScanSchema = z.object({
  projectId: z.string(),
  scanType: z.enum(["FULL", "INCREMENTAL", "SAST_ONLY", "SCA_ONLY", "SECRETS_ONLY"]).default("FULL"),
  branch: z.string().optional(),
  commitSha: z.string().optional(),
  baseSha: z.string().optional(),
  repoUrl: z.string().optional(),
});

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  try {
    const contentType = req.headers.get("content-type") || "";
    let scanParams: z.infer<typeof createScanSchema>;
    let fileBuffer: Buffer | null = null;

    if (contentType.includes("multipart/form-data")) {
      const formData = await req.formData();
      const file = formData.get("file") as File | null;
      const data = formData.get("data") as string | null;

      scanParams = createScanSchema.parse(JSON.parse(data || "{}"));

      if (file) {
        const arrayBuffer = await file.arrayBuffer();
        fileBuffer = Buffer.from(arrayBuffer);
      }
    } else {
      const body = await req.json();
      scanParams = createScanSchema.parse(body);
    }

    // Verify project exists and user has access
    const project = await prisma.project.findUnique({
      where: { id: scanParams.projectId },
      include: { organization: true, buildGate: true },
    });

    if (!project) {
      return NextResponse.json({ error: "Project not found" }, { status: 404 });
    }

    // Get org settings
    const orgSettings = await prisma.orgSettings.findUnique({
      where: { organizationId: project.organizationId },
    });

    // Create scan record
    const scan = await prisma.scan.create({
      data: {
        projectId: scanParams.projectId,
        scanType: scanParams.scanType,
        branch: scanParams.branch,
        commitSha: scanParams.commitSha,
        baseSha: scanParams.baseSha,
        sourceType: fileBuffer ? "UPLOAD" : scanParams.repoUrl ? "GIT_CLONE" : "UPLOAD",
        triggeredBy: auth.session.user.id,
        status: "QUEUED",
      },
    });

    // Upload source file to MinIO if provided
    let sourceRef = "";
    if (fileBuffer) {
      await ensureBucket();
      sourceRef = `scans/${scan.id}/source.zip`;
      await uploadObject(sourceRef, fileBuffer, "application/zip");
    } else if (scanParams.repoUrl) {
      sourceRef = scanParams.repoUrl;
    }

    // Update scan with sourceRef
    await prisma.scan.update({
      where: { id: scan.id },
      data: { sourceRef },
    });

    // Enqueue job
    const jobData: ScanJobData = {
      scanId: scan.id,
      projectId: scanParams.projectId,
      sourceType: fileBuffer ? "UPLOAD" : "GIT_CLONE",
      sourceRef,
      scanType: scanParams.scanType,
      baseSha: scanParams.baseSha,
      commitSha: scanParams.commitSha,
      repoUrl: scanParams.repoUrl,
      branch: scanParams.branch,
      orgSettings: {
        llmProvider: orgSettings?.llmProvider || "openai",
        llmBaseUrl: orgSettings?.llmBaseUrl || "https://api.openai.com/v1",
        llmModel: orgSettings?.llmModel || "gpt-4o-mini",
        llmApiKey: orgSettings?.llmApiKey || undefined,
        enableLlmSast: orgSettings?.enableLlmSast ?? true,
        enableLlmSecrets: orgSettings?.enableLlmSecrets ?? true,
        osvApiUrl: orgSettings?.osvApiUrl || "https://api.osv.dev",
      },
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

    return NextResponse.json({ scanId: scan.id, status: "QUEUED" }, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: "Invalid input", details: error.issues }, { status: 400 });
    }
    console.error("Failed to create scan:", error);
    return NextResponse.json({ error: "Failed to create scan" }, { status: 500 });
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
