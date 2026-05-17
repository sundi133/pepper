import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";

const TYPE_TO_PATH: Record<string, string> = {
  SCAN_LOG: "log",
  SBOM_CYCLONEDX: "cyclonedx",
  SBOM_SPDX: "spdx",
  CONTAINER_REPORT: "container",
  DAST_REPORT: "dast",
  SARIF: "sarif",
  SIGNATURE: "signature",
};

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const { scanId } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: { id: true },
  });
  if (!scan) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const artifacts = await prisma.scanArtifact.findMany({
    where: { scanId },
    select: { type: true, size: true, createdAt: true },
    orderBy: { createdAt: "asc" },
  });

  return NextResponse.json({
    artifacts: artifacts.map((a) => ({
      type: a.type,
      size: a.size,
      createdAt: a.createdAt,
      downloadPath: `/api/scans/${scanId}/artifacts/${TYPE_TO_PATH[a.type] || a.type.toLowerCase()}`,
    })),
  });
}
