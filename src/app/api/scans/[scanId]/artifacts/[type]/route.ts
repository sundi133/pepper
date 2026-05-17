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

  if (type.toLowerCase() !== "log") {
    return NextResponse.json(
      { error: "Invalid artifact type. Use: log" },
      { status: 400 },
    );
  }

  const artifact = await prisma.scanArtifact.findFirst({
    where: {
      scanId,
      type: "SCAN_LOG",
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
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="scan.log"`,
      },
    });
  } catch {
    return NextResponse.json(
      { error: "Failed to download artifact" },
      { status: 500 },
    );
  }
}
