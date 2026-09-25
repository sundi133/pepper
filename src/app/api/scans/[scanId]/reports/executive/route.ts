import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  buildExecutiveHtml,
  buildExecutivePdf,
  buildExecutiveSummary,
} from "@/lib/reports/executive-report";
import { REPORT_HTML_CSP, reportFileSlug } from "@/lib/reports/report-html";

/**
 * GET /api/scans/[scanId]/reports/executive?format=html|pdf
 *
 * Business-level summary of a scan for leadership: risk posture, open issues
 * by severity, top risks, risk areas, OWASP exposure and a remediation
 * roadmap. No code snippets or reproduction steps.
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const format = new URL(req.url).searchParams.get("format") || "html";
  if (format !== "html" && format !== "pdf") {
    return NextResponse.json(
      { error: "Unsupported format. Use format=html or format=pdf." },
      { status: 400 },
    );
  }

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: {
      id: true,
      status: true,
      scanType: true,
      branch: true,
      commitSha: true,
      sourceType: true,
      sourceRef: true,
      gateResult: true,
      createdAt: true,
      completedAt: true,
      filesScanned: true,
      depsScanned: true,
      autoResolvedCount: true,
      project: { select: { name: true, repoUrl: true } },
    },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const findings = await prisma.finding.findMany({
    where: { scanId, scan: { project: { organizationId: orgId } } },
    select: {
      id: true,
      scanner: true,
      severity: true,
      title: true,
      status: true,
      cweId: true,
      filePath: true,
      riskScore: true,
      isNew: true,
      metadata: true,
    },
  });

  const summary = buildExecutiveSummary(scan, findings);
  const timestamp = new Date().toISOString().slice(0, 10);
  const fileBase = `${reportFileSlug(scan.project?.name)}-executive-${timestamp}`;

  if (format === "pdf") {
    try {
      const pdf = await buildExecutivePdf(summary);
      return new NextResponse(new Uint8Array(pdf), {
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": `inline; filename="${fileBase}.pdf"`,
          "Cache-Control": "no-store",
        },
      });
    } catch (e) {
      console.error("Executive PDF generation failed:", e);
      return NextResponse.json(
        { error: "Failed to generate executive PDF report" },
        { status: 500 },
      );
    }
  }

  return new NextResponse(buildExecutiveHtml(summary), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Disposition": `inline; filename="${fileBase}.html"`,
      "Cache-Control": "no-store",
      "Content-Security-Policy": REPORT_HTML_CSP,
    },
  });
}
