import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { Prisma } from "@/generated/prisma/client";
import { prisma } from "@/lib/prisma";
import { requireAuth, requireRole, getActiveOrgId } from "@/lib/auth-guard";
import { getLlmConfig } from "@/lib/llm-gateway";
import { getReportQueue } from "@/lib/queue";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import type { TemplateSnapshot } from "@/lib/custom-reports/agent";

const bodySchema = z.object({
  templateId: z.string().min(1).max(64),
  instructions: z.string().max(2000).nullish(),
});

/** Scans whose findings are final enough to report on. */
const REPORTABLE_STATUSES = new Set(["COMPLETED", "STOPPED"]);

/**
 * POST /api/scans/[scanId]/custom-reports — generate an AI report from one of
 * the organization's templates. Runs in the worker; poll
 * /api/scans/[scanId]/custom-reports/[reportId] for progress.
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const role = await requireRole(orgId, "DEVELOPER");
  if ("error" in role) return role.error;

  const { scanId } = await params;
  const parsed = bodySchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Choose a template (instructions are limited to 2,000 characters)." }, { status: 400 });
  }

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: { id: true, status: true },
  });
  if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  if (!REPORTABLE_STATUSES.has(scan.status)) {
    return NextResponse.json({ error: "Custom reports can be generated once the scan has finished." }, { status: 409 });
  }

  const template = await prisma.reportTemplate.findFirst({
    where: { id: parsed.data.templateId, organizationId: orgId },
  });
  if (!template) return NextResponse.json({ error: "Template not found" }, { status: 404 });

  const orgSettings = await prisma.orgSettings.findUnique({ where: { organizationId: orgId } });
  const llm = getLlmConfig(orgSettings);
  if (!llm.apiKey && llm.provider !== "ollama") {
    return NextResponse.json(
      { error: "No LLM is configured. Set a provider and API key under Settings → LLM.", code: "LLM_NOT_CONFIGURED" },
      { status: 400 },
    );
  }

  const active = await prisma.customReport.findFirst({
    where: { scanId, status: { in: ["QUEUED", "RUNNING"] } },
    select: { id: true },
  });
  if (active) {
    return NextResponse.json(
      { error: "A custom report is already being generated for this scan.", reportId: active.id, code: "REPORT_IN_PROGRESS" },
      { status: 409 },
    );
  }

  const snapshot: TemplateSnapshot = {
    name: template.name,
    format: template.format,
    body: template.body,
    instructions: template.instructions,
  };
  const report = await prisma.customReport.create({
    data: {
      organizationId: orgId,
      scanId,
      templateId: template.id,
      templateName: template.name,
      templateSnapshot: snapshot as unknown as Prisma.InputJsonValue,
      extraInstructions: parsed.data.instructions?.trim() || null,
      createdBy: auth.session.user.id,
      stage: "Queued",
    },
    select: { id: true },
  });

  try {
    await getReportQueue().add("custom-report", { reportId: report.id }, { jobId: report.id });
  } catch (e) {
    await prisma.customReport.update({
      where: { id: report.id },
      data: {
        status: "FAILED",
        stage: "Failed",
        completedAt: new Date(),
        errorMessage: `Could not queue the report: ${e instanceof Error ? e.message : String(e)}`,
      },
    });
    return NextResponse.json({ error: "Could not queue the report. Is Redis reachable?" }, { status: 503 });
  }

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "report.custom_requested",
    resource: "report",
    resourceId: report.id,
    details: { scanId, templateId: template.id, template: template.name, extraInstructions: !!parsed.data.instructions?.trim() },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json({ reportId: report.id }, { status: 201 });
}

/** GET /api/scans/[scanId]/custom-reports — custom reports generated for this scan. */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const { scanId } = await params;
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: { id: true },
  });
  if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });

  const reports = await prisma.customReport.findMany({
    where: { scanId, organizationId: orgId },
    orderBy: { createdAt: "desc" },
    take: 20,
    select: {
      id: true,
      templateId: true,
      templateName: true,
      title: true,
      status: true,
      progress: true,
      stage: true,
      model: true,
      errorMessage: true,
      createdBy: true,
      createdAt: true,
      completedAt: true,
    },
  });
  return NextResponse.json({ reports });
}
