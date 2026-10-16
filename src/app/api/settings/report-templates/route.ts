import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import { normalizeTemplateBody } from "@/lib/custom-reports/template";
import { isDuplicateName, templateSchema } from "@/lib/custom-reports/template-schema";

/** GET /api/settings/report-templates — the organization's report templates. */
export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const templates = await prisma.reportTemplate.findMany({
    where: { organizationId: orgId },
    orderBy: { name: "asc" },
    select: {
      id: true,
      name: true,
      description: true,
      format: true,
      body: true,
      instructions: true,
      sourceFileName: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  return NextResponse.json({ templates });
}

/** POST /api/settings/report-templates — create a template (Admin / Security). */
export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const parsed = templateSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid input", details: parsed.error.issues }, { status: 400 });
  }
  const data = parsed.data;
  if (!normalizeTemplateBody(data.format, data.body)) {
    return NextResponse.json({ error: "The template has no text content." }, { status: 400 });
  }

  try {
    const template = await prisma.reportTemplate.create({
      data: {
        organizationId: orgId,
        name: data.name,
        description: data.description || null,
        format: data.format,
        body: data.body,
        instructions: data.instructions || null,
        sourceFileName: data.sourceFileName || null,
        createdBy: auth.session.user.id,
      },
    });
    await writeAuditLog({
      organizationId: orgId,
      userId: auth.session.user.id,
      action: "report_template.created",
      resource: "report_template",
      resourceId: template.id,
      details: { name: template.name, format: template.format },
      ipAddress: ipFromHeaders(req.headers),
    });
    return NextResponse.json(template, { status: 201 });
  } catch (e) {
    if (isDuplicateName(e)) {
      return NextResponse.json({ error: "A template with this name already exists." }, { status: 409 });
    }
    return NextResponse.json({ error: "Failed to create template" }, { status: 500 });
  }
}
