import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import { normalizeTemplateBody } from "@/lib/custom-reports/template";
import { isDuplicateName, templateUpdateSchema } from "@/lib/custom-reports/template-schema";

type Params = { params: Promise<{ templateId: string }> };

/** GET /api/settings/report-templates/[templateId] */
export async function GET(_req: NextRequest, { params }: Params) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const { templateId } = await params;
  const template = await prisma.reportTemplate.findFirst({ where: { id: templateId, organizationId: orgId } });
  if (!template) return NextResponse.json({ error: "Template not found" }, { status: 404 });
  return NextResponse.json(template);
}

/** PATCH /api/settings/report-templates/[templateId] — edit (Admin / Security). */
export async function PATCH(req: NextRequest, { params }: Params) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const { templateId } = await params;
  const parsed = templateUpdateSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid input", details: parsed.error.issues }, { status: 400 });
  }
  const existing = await prisma.reportTemplate.findFirst({
    where: { id: templateId, organizationId: orgId },
    select: { id: true, format: true, body: true },
  });
  if (!existing) return NextResponse.json({ error: "Template not found" }, { status: 404 });

  const data = parsed.data;
  if (!normalizeTemplateBody(data.format ?? existing.format, data.body ?? existing.body)) {
    return NextResponse.json({ error: "The template has no text content." }, { status: 400 });
  }

  try {
    const template = await prisma.reportTemplate.update({
      where: { id: templateId },
      data: {
        ...(data.name !== undefined ? { name: data.name } : {}),
        ...(data.description !== undefined ? { description: data.description || null } : {}),
        ...(data.format !== undefined ? { format: data.format } : {}),
        ...(data.body !== undefined ? { body: data.body } : {}),
        ...(data.instructions !== undefined ? { instructions: data.instructions || null } : {}),
        ...(data.sourceFileName !== undefined ? { sourceFileName: data.sourceFileName || null } : {}),
      },
    });
    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "report_template.updated",
      resource: "report_template",
      resourceId: templateId,
      details: { name: template.name, changed: Object.keys(data) },
      ipAddress: ipFromHeaders(req.headers),
    });
    return NextResponse.json(template);
  } catch (e) {
    if (isDuplicateName(e)) {
      return NextResponse.json({ error: "A template with this name already exists." }, { status: 409 });
    }
    return NextResponse.json({ error: "Failed to update template" }, { status: 500 });
  }
}

/**
 * DELETE /api/settings/report-templates/[templateId] (Admin / Security).
 * Reports already generated from it are kept (they store a snapshot).
 */
export async function DELETE(req: NextRequest, { params }: Params) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const { templateId } = await params;
  const result = await prisma.reportTemplate.deleteMany({ where: { id: templateId, organizationId: orgId } });
  if (result.count === 0) return NextResponse.json({ error: "Template not found" }, { status: 404 });

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "report_template.deleted",
    resource: "report_template",
    resourceId: templateId,
    ipAddress: ipFromHeaders(req.headers),
  });
  return NextResponse.json({ success: true });
}
