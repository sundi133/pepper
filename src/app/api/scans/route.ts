import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { z } from "zod";
import { ipFromHeaders } from "@/lib/audit-log";
import { createScanSchema, queueNewScan } from "@/lib/scan-create";
import { scanListWhere } from "@/lib/scan-queries";
import { maxUploadBytes, maxUploadMb } from "@/lib/upload-limits";
import { mobilePlatformOf } from "@/lib/mobile-platform";

import {
  ARTIFACT_MIME_TYPES,
  UPLOADABLE_ARTIFACT_EXTENSIONS,
  isCompiledArtifactUpload,
} from "@/lib/compiled-scan/upload";

const ALLOWED_EXTENSIONS = [".zip", ".tar.gz", ".tgz", ".tar"] as const;
const ALLOWED_MIME_TYPES = new Set([
  "application/zip",
  "application/x-zip-compressed",
  "application/x-tar",
  "application/gzip",
  "application/x-gzip",
  "application/x-compressed-tar",
]);

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const roleAuth = await requireRole(orgId, "DEVELOPER");
  if ("error" in roleAuth) return roleAuth.error;

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
        // Validate file size
        if (file.size > maxUploadBytes()) {
          return NextResponse.json(
            {
              error: `File too large. Maximum allowed size is ${maxUploadMb()} MB`,
            },
            { status: 400 },
          );
        }

        // Validate file extension: a source archive, or a single compiled
        // artifact (decompiled by the worker's compiled-code scan).
        const fileName = file.name.toLowerCase();
        const isArtifact = isCompiledArtifactUpload(fileName);
        const hasAllowedExt =
          isArtifact ||
          ALLOWED_EXTENSIONS.some((ext) => fileName.endsWith(ext));
        if (!hasAllowedExt) {
          return NextResponse.json(
            {
              error: `Invalid file type. Allowed extensions: ${[...ALLOWED_EXTENSIONS, ...UPLOADABLE_ARTIFACT_EXTENSIONS].join(", ")}`,
            },
            { status: 400 },
          );
        }

        // Validate MIME type
        if (
          file.type &&
          !(isArtifact ? ARTIFACT_MIME_TYPES : ALLOWED_MIME_TYPES).has(file.type)
        ) {
          return NextResponse.json(
            {
              error: isArtifact
                ? "Invalid file MIME type for a compiled artifact"
                : "Invalid file MIME type. Only archive files (zip, tar, tar.gz) are accepted",
            },
            { status: 400 },
          );
        }

        // Only the GPT-6 Astra review looks inside an iOS app; without it the
        // scan would report "no findings" for a file nothing inspected.
        if (mobilePlatformOf(fileName) === "ios" && !scanParams.aiMobileReview) {
          return NextResponse.json(
            {
              error:
                "iOS apps (.ipa) are only scanned by the GPT-6 Astra review: request it (aiMobileReview) to scan this file",
            },
            { status: 400 },
          );
        }

        const arrayBuffer = await file.arrayBuffer();
        fileBuffer = Buffer.from(arrayBuffer);
        originalFileName = file.name;
      }
    } else {
      const body = await req.json();
      scanParams = createScanSchema.parse(body);
    }

    const result = await queueNewScan({
      orgId,
      userId: auth.session.user.id,
      scanParams,
      fileBuffer,
      originalFileName,
      ipAddress: ipFromHeaders(req.headers),
    });
    if (!result.ok) {
      return NextResponse.json({ error: result.error }, { status: result.status });
    }

    return NextResponse.json(
      { scanId: result.scanId, projectId: result.projectId, status: "QUEUED" },
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
  const q = searchParams.get("q")?.trim().slice(0, 200);
  const page = parseInt(searchParams.get("page") || "1");
  const limit = parseInt(searchParams.get("limit") || "20");

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  // Search: repository name, source (repo URL or upload name), branch, or scan id.
  const where = scanListWhere({ orgId, projectId, status, q });

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
