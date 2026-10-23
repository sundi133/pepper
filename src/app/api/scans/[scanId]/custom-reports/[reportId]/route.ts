import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, requireRole, getActiveOrgId } from "@/lib/auth-guard";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";

type Params = { params: Promise<{ scanId: string; reportId: string }> };

/** GET /api/scans/[scanId]/custom-reports/[reportId] — status and progress. */
export async function GET(_req: NextRequest, { params }: Params) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const { scanId, reportId } = await params;
  const report = await prisma.customReport.findFirst({
    where: { id: reportId, scanId, organizationId: orgId },
    select: {
      id: true,
      scanId: true,
      templateId: true,
      templateName: true,
      title: true,
      extraInstructions: true,
      status: true,
      progress: true,
      stage: true,
      steps: true,
      provider: true,
      model: true,
      llmCalls: true,
      grounding: true,
      errorMessage: true,
      createdBy: true,
      createdAt: true,
      startedAt: true,
      completedAt: true,
    },
  });
  if (!report) return NextResponse.json({ error: "Report not found" }, { status: 404 });
  return NextResponse.json(report);
}

/**
 * DELETE /api/scans/[scanId]/custom-reports/[reportId] — remove a finished
 * report. Its author may delete it; Admin / Security may delete any.
 */
export async function DELETE(req: NextRequest, { params }: Params) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const role = await requireRole(orgId, "DEVELOPER");
  if ("error" in role) return role.error;

  const { scanId, reportId } = await params;
  const report = await prisma.customReport.findFirst({
    where: { id: reportId, scanId, organizationId: orgId },
    select: { id: true, status: true, createdBy: true, templateName: true },
  });
  if (!report) return NextResponse.json({ error: "Report not found" }, { status: 404 });
  const privileged = role.membership.role === "ADMIN" || role.membership.role === "SECURITY";
  if (!privileged && report.createdBy !== auth.session.user.id) {
    return NextResponse.json({ error: "Only the report's author or an Admin / Security member can delete it." }, { status: 403 });
  }
  if (report.status === "QUEUED" || report.status === "RUNNING") {
    return NextResponse.json({ error: "The report is still being generated." }, { status: 409 });
  }

  await prisma.customReport.delete({ where: { id: reportId } });
  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "report.custom_deleted",
    resource: "report",
    resourceId: reportId,
    details: { scanId, template: report.templateName },
    ipAddress: ipFromHeaders(req.headers),
  });
  return NextResponse.json({ success: true });
}
