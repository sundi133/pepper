import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getActiveOrgId, requireRole } from "@/lib/auth-guard";
import { getLlmConfig } from "@/lib/llm-gateway";
import { generateFindingDetails } from "@/lib/generate-finding-details";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ findingId: string }> }
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { findingId } = await params;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "DEVELOPER");
  if ("error" in roleAuth) return roleAuth.error;

  const finding = await prisma.finding.findFirst({
    where: { id: findingId },
    include: {
      scan: {
        select: {
          projectId: true,
          project: {
            select: {
              organizationId: true,
              organization: {
                select: {
                  settings: true,
                },
              },
            },
          },
        },
      },
    },
  });

  if (!finding || finding.scan?.project?.organizationId !== orgId) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  const config = getLlmConfig(
    finding.scan?.project?.organization?.settings as Record<string, unknown> | null
  );

  try {
    const details = await generateFindingDetails(
      {
        id: finding.id,
        title: finding.title,
        cweId: finding.cweId,
        severity: finding.severity,
        filePath: finding.filePath,
        startLine: finding.startLine,
        endLine: finding.endLine,
        description: finding.description,
      },
      config,
    );

    if (!details) {
      return NextResponse.json(
        { error: "Failed to generate vulnerability details" },
        { status: 500 }
      );
    }

    const updatedMetadata = {
      ...((finding.metadata as Record<string, unknown>) || {}),
      generatedDetails: details,
    };

    await prisma.finding.update({
      where: { id: findingId },
      data: { metadata: updatedMetadata as object },
    });

    return NextResponse.json(updatedMetadata.generatedDetails);
  } catch (error) {
    console.error("Error generating vulnerability details:", error);
    return NextResponse.json(
      { error: "Failed to generate details" },
      { status: 500 }
    );
  }
}
