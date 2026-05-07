import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  enrichFindingWithReport,
  findingHasStoredReport,
} from "@/lib/finding-report";
import { z } from "zod";

const updateStatusSchema = z.object({
  status: z.enum([
    "OPEN",
    "IN_PROGRESS",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "RESOLVED",
  ]),
  statusNote: z.string().optional(),
});

export async function PATCH(
  req: NextRequest,
  { params }: { params: Promise<{ findingId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { findingId } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  try {
    const body = await req.json();
    const data = updateStatusSchema.parse(body);

    const existing = await prisma.finding.findFirst({
      where: {
        id: findingId,
        scan: { project: { organizationId: orgId } },
      },
      select: { id: true },
    });
    if (!existing) {
      return NextResponse.json({ error: "Finding not found" }, { status: 404 });
    }

    const finding = await prisma.finding.update({
      where: { id: findingId },
      data: {
        status: data.status,
        statusNote: data.statusNote || null,
        statusUpdatedBy: auth.session.user.id,
        statusUpdatedAt: new Date(),
      },
    });

    const enrichedFinding = enrichFindingWithReport(finding);
    if (!findingHasStoredReport(finding)) {
      await prisma.finding.update({
        where: { id: finding.id },
        data: { metadata: enrichedFinding.metadata as object },
      });
    }
    return NextResponse.json(enrichedFinding);
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to update finding" },
      { status: 500 },
    );
  }
}

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ findingId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { findingId } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const finding = await prisma.finding.findFirst({
    where: {
      id: findingId,
      scan: { project: { organizationId: orgId } },
    },
  });

  if (!finding) {
    return NextResponse.json({ error: "Finding not found" }, { status: 404 });
  }

  const enrichedFinding = enrichFindingWithReport(finding);
  if (!findingHasStoredReport(finding)) {
    await prisma.finding.update({
      where: { id: finding.id },
      data: { metadata: enrichedFinding.metadata as object },
    });
  }

  return NextResponse.json(enrichedFinding);
}
