import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { downloadObject } from "@/lib/minio";

type ArtifactKind =
  | "SCAN_LOG"
  | "SBOM_CYCLONEDX"
  | "SBOM_SPDX"
  | "CONTAINER_REPORT"
  | "DAST_REPORT"
  | "SARIF"
  | "SIGNATURE";

const TYPE_MAP: Record<
  string,
  { type: ArtifactKind; contentType: string; filename: string }
> = {
  log: {
    type: "SCAN_LOG",
    contentType: "application/json",
    filename: "scan.log",
  },
  "sbom-cyclonedx": {
    type: "SBOM_CYCLONEDX",
    contentType: "application/vnd.cyclonedx+json",
    filename: "sbom.cyclonedx.json",
  },
  cyclonedx: {
    type: "SBOM_CYCLONEDX",
    contentType: "application/vnd.cyclonedx+json",
    filename: "sbom.cyclonedx.json",
  },
  "sbom-spdx": {
    type: "SBOM_SPDX",
    contentType: "application/spdx+json",
    filename: "sbom.spdx.json",
  },
  spdx: {
    type: "SBOM_SPDX",
    contentType: "application/spdx+json",
    filename: "sbom.spdx.json",
  },
  container: {
    type: "CONTAINER_REPORT",
    contentType: "application/json",
    filename: "container-report.json",
  },
  dast: {
    type: "DAST_REPORT",
    contentType: "application/json",
    filename: "dast-report.json",
  },
  sarif: {
    type: "SARIF",
    contentType: "application/sarif+json",
    filename: "findings.sarif",
  },
  signature: {
    type: "SIGNATURE",
    contentType: "application/json",
    filename: "signature.json",
  },
};

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string; type: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId, type } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const entry = TYPE_MAP[type.toLowerCase()];
  if (!entry) {
    return NextResponse.json(
      {
        error: `Invalid artifact type. Use one of: ${Object.keys(TYPE_MAP).join(", ")}`,
      },
      { status: 400 },
    );
  }

  const artifact = await prisma.scanArtifact.findFirst({
    where: {
      scanId,
      type: entry.type,
      scan: { project: { organizationId: orgId } },
    },
  });

  if (!artifact) {
    return NextResponse.json({ error: "Artifact not found" }, { status: 404 });
  }

  try {
    const data = await downloadObject(artifact.objectKey);
    return new NextResponse(new Uint8Array(data), {
      headers: {
        "Content-Type": entry.contentType,
        "Content-Disposition": `attachment; filename="${entry.filename}"`,
      },
    });
  } catch {
    return NextResponse.json(
      { error: "Failed to download artifact" },
      { status: 500 },
    );
  }
}
