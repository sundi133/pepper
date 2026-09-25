import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  buildComplianceHtml,
  buildCompliancePdf,
  type ComplianceExportInput,
  type ComplianceFrameworkReport,
} from "@/lib/reports/compliance-report";
import { REPORT_HTML_CSP, reportFileSlug } from "@/lib/reports/report-html";

/**
 * GET /api/scans/[scanId]/compliance/export?format=html|pdf
 *
 * Renders already-generated compliance results as a downloadable report. Reads
 * only the per-framework cache written by the compliance stream/GET routes —
 * it never triggers an LLM run.
 *
 * Query params:
 *   ?frameworks=owasp-top-10,pci-dss   Framework slugs to include (required).
 *   ?mode=deep|fast                    Mapping mode the results were built with.
 *   ?model=<id>                        Model used for deep mode (omit for crosswalk).
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  const url = new URL(req.url);
  const format = url.searchParams.get("format") || "html";
  if (format !== "html" && format !== "pdf") {
    return NextResponse.json(
      { error: "Unsupported format. Use format=html or format=pdf." },
      { status: 400 },
    );
  }
  const slugs = (url.searchParams.get("frameworks") || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (slugs.length === 0) {
    return NextResponse.json(
      { error: "Select at least one framework (frameworks=slug1,slug2)." },
      { status: 400 },
    );
  }
  const mode = url.searchParams.get("mode") === "fast" ? "fast" : "deep";
  const model = url.searchParams.get("model")?.trim() || null;
  // Must match the cache key built in the compliance routes.
  const modelSeg = model ?? "det";

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: {
      scannerProgress: true,
      commitSha: true,
      createdAt: true,
      completedAt: true,
      _count: { select: { findings: true } },
      project: { select: { name: true, repoUrl: true } },
    },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const scanMeta = (scan.scannerProgress as Record<string, unknown>) || {};
  const cache =
    (scanMeta._complianceByFramework as Record<string, unknown>) || {};

  const reports: ComplianceFrameworkReport[] = [];
  const missing: string[] = [];
  for (const slug of slugs) {
    const cached = cache[`${slug}::${mode}::${modelSeg}`];
    if (cached && typeof cached === "object") {
      reports.push(cached as ComplianceFrameworkReport);
    } else {
      missing.push(slug);
    }
  }
  if (reports.length === 0) {
    return NextResponse.json(
      {
        error:
          "No generated compliance results found for this selection. Generate the report first.",
        missing,
      },
      { status: 404 },
    );
  }

  const input: ComplianceExportInput = {
    projectName: scan.project?.name || "Scan",
    repoUrl: scan.project?.repoUrl?.trim() || null,
    commitSha: scan.commitSha,
    scanDate: scan.completedAt ?? scan.createdAt,
    mode,
    model: mode === "deep" ? model : null,
    totalFindings: scan._count.findings,
    reports,
  };

  const timestamp = new Date().toISOString().slice(0, 10);
  const fileBase = `${reportFileSlug(input.projectName)}-compliance-${timestamp}`;

  if (format === "pdf") {
    try {
      const pdf = await buildCompliancePdf(input);
      return new NextResponse(new Uint8Array(pdf), {
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": `inline; filename="${fileBase}.pdf"`,
          "Cache-Control": "no-store",
        },
      });
    } catch (e) {
      console.error("Compliance PDF generation failed:", e);
      return NextResponse.json(
        { error: "Failed to generate compliance PDF report" },
        { status: 500 },
      );
    }
  }

  return new NextResponse(buildComplianceHtml(input), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Disposition": `inline; filename="${fileBase}.html"`,
      "Cache-Control": "no-store",
      "Content-Security-Policy": REPORT_HTML_CSP,
    },
  });
}
