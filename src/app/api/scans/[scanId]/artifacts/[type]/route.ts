import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { downloadObject } from "@/lib/minio";

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

  const typeMap: Record<string, string> = {
    sarif: "SARIF",
    sbom: "SBOM_CYCLONEDX",
    log: "SCAN_LOG",
  };

  const artifactType = typeMap[type.toLowerCase()];
  if (!artifactType) {
    return NextResponse.json(
      { error: "Invalid artifact type. Use: sarif, sbom, or log" },
      { status: 400 },
    );
  }

  const artifact = await prisma.scanArtifact.findFirst({
    where: {
      scanId,
      type: artifactType as "SARIF" | "SBOM_CYCLONEDX" | "SCAN_LOG",
      scan: { project: { organizationId: orgId } },
    },
  });

  if (!artifact) {
    return NextResponse.json({ error: "Artifact not found" }, { status: 404 });
  }

  try {
    const data = await downloadObject(artifact.objectKey);
    const filename =
      type === "sarif"
        ? "results.sarif.json"
        : type === "sbom"
          ? "sbom.cyclonedx.json"
          : "scan.log";

    return new NextResponse(new Uint8Array(data), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${filename}"`,
      },
    });
  } catch {
    return NextResponse.json(
      { error: "Failed to download artifact" },
      { status: 500 },
    );
  }
}
