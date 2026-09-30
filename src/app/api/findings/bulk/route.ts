import { NextRequest, NextResponse } from "next/server";
import { isRiskDecisionStatus, requireRiskDecisionRole } from "@/lib/permissions";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { z } from "zod";
import { generateSuppressionRule } from "@/lib/suppression-rules";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

const bulkUpdateSchema = z.object({
  findingIds: z.array(z.string()).min(1).max(500),
  status: z.enum([
    "OPEN",
    "IN_PROGRESS",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "RESOLVED",
  ]),
  statusNote: z.string().optional(),
});

export async function PATCH(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "DEVELOPER");
  if ("error" in roleAuth) return roleAuth.error;

  try {
    const body = await req.json();
    const data = bulkUpdateSchema.parse(body);
    if (isRiskDecisionStatus(data.status)) {
      const denied = await requireRiskDecisionRole(orgId);
      if (denied) return denied;
    }

    const result = await prisma.finding.updateMany({
      where: {
        id: { in: data.findingIds },
        scan: { project: { organizationId: orgId } },
      },
      data: {
        status: data.status,
        statusNote: data.statusNote || null,
        statusUpdatedBy: auth.session.user.id,
        statusUpdatedAt: new Date(),
      },
    });

    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "finding.status_changed",
      resource: "finding",
      details: {
        to: data.status,
        note: data.statusNote || null,
        bulk: true,
        updated: result.count,
        findingIds: data.findingIds.slice(0, 500),
      },
      ipAddress: ipFromHeaders(req.headers),
    });

    // Auto-create suppression rules when bulk-marking as false positive
    if (data.status === "FALSE_POSITIVE" && result.count > 0) {
      try {
        const findings = await prisma.finding.findMany({
          where: {
            id: { in: data.findingIds },
            scan: { project: { organizationId: orgId } },
          },
          select: {
            id: true, ruleId: true, cweId: true, scanner: true,
            filePath: true, title: true, snippet: true,
            scan: { select: { projectId: true } },
          },
        });
        await Promise.allSettled(
          findings.map((f) =>
            generateSuppressionRule({
              organizationId: orgId,
              projectId: f.scan.projectId,
              finding: f,
              reason: data.statusNote || "Bulk marked as false positive",
              userId: auth.session.user.id,
              source: "bulk",
            }),
          ),
        );
      } catch {
        // Non-blocking
      }
    }

    return NextResponse.json({
      updated: result.count,
      status: data.status,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to update findings" },
      { status: 500 },
    );
  }
}
