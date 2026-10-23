import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getActiveOrgId } from "@/lib/auth-guard";
import { REPORT_HTML_CSP, reportFileSlug } from "@/lib/reports/report-html";
import { buildCustomReportMarkdown, buildCustomReportPdf, type ReportMeta } from "@/lib/custom-reports/render";

/**
 * GET /api/scans/[scanId]/custom-reports/[reportId]/download?format=html|md|pdf
 *
 * HTML is the stored, sanitized page (served under the report CSP: no
 * scripts, no external resources). Markdown and PDF are rendered from the
 * stored Markdown with the same AI-generation footer.
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string; reportId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const format = new URL(req.url).searchParams.get("format") || "html";
  if (format !== "html" && format !== "md" && format !== "pdf") {
    return NextResponse.json({ error: "Unsupported format. Use format=html, md or pdf." }, { status: 400 });
  }

  const { scanId, reportId } = await params;
  const report = await prisma.customReport.findFirst({
    where: { id: reportId, scanId, organizationId: orgId },
    select: {
      status: true,
      title: true,
      templateName: true,
      markdown: true,
      html: true,
      model: true,
      completedAt: true,
      scan: { select: { project: { select: { name: true } } } },
    },
  });
  if (!report) return NextResponse.json({ error: "Report not found" }, { status: 404 });
  if (report.status !== "COMPLETED" || !report.markdown || !report.html) {
    return NextResponse.json({ error: "The report is not ready." }, { status: 409 });
  }

  const meta: ReportMeta = {
    title: report.title || report.templateName,
    templateName: report.templateName,
    projectName: report.scan.project.name,
    scanId,
    generatedAt: report.completedAt ?? new Date(),
    model: report.model ?? "unknown",
  };
  const fileBase = `${reportFileSlug(meta.projectName)}-${reportFileSlug(meta.templateName)}-${meta.generatedAt.toISOString().slice(0, 10)}`;

  if (format === "md") {
    return new NextResponse(buildCustomReportMarkdown(report.markdown, meta), {
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": `attachment; filename="${fileBase}.md"`,
        "Cache-Control": "no-store",
      },
    });
  }
  if (format === "pdf") {
    try {
      const pdf = await buildCustomReportPdf(report.markdown, meta);
      return new NextResponse(new Uint8Array(pdf), {
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": `inline; filename="${fileBase}.pdf"`,
          "Cache-Control": "no-store",
        },
      });
    } catch (e) {
      console.error("Custom report PDF generation failed:", e);
      return NextResponse.json({ error: "Failed to generate the PDF" }, { status: 500 });
    }
  }
  return new NextResponse(report.html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Disposition": `inline; filename="${fileBase}.html"`,
      "Cache-Control": "no-store",
      "Content-Security-Policy": REPORT_HTML_CSP,
      "X-Content-Type-Options": "nosniff",
    },
  });
}
