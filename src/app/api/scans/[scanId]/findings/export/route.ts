import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth-guard";
import {
  buildSecurityScanReport,
  renderSecurityScanReportMarkdown,
} from "@/lib/security-report";
import { buildSarif } from "@/scanners/sarif-builder";
import type { RawFinding } from "@/scanners/types";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;
  const { searchParams } = new URL(req.url);
  const format = searchParams.get("format") || "csv";

  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      id: true,
      scannerProgress: true,
      filesScanned: true,
      project: { select: { name: true } },
    },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const findings = await prisma.finding.findMany({
    where: { scanId },
    orderBy: [{ severity: "asc" }, { scanner: "asc" }, { filePath: "asc" }],
  });

  const progress =
    scan.scannerProgress &&
    typeof scan.scannerProgress === "object" &&
    !Array.isArray(scan.scannerProgress)
      ? (scan.scannerProgress as Record<string, unknown>)
      : {};

  const architectureOverview =
    typeof progress.architectureOverview === "string"
      ? progress.architectureOverview
      : undefined;
  const rulesVersion =
    typeof progress.rulesVersion === "string"
      ? progress.rulesVersion
      : "pepper-sast-engine";

  const report = buildSecurityScanReport({
    scanId,
    projectName: scan.project?.name || undefined,
    findings,
    architectureOverview,
    appendix: {
      rulesVersion,
      assumptions: [
        "Routes and HTTP surface are inferred heuristically when the repository is unavailable.",
        `Approximately ${scan.filesScanned} files were enumerated during the worker scan.`,
      ],
    },
  });

  const timestamp = new Date().toISOString().slice(0, 10);
  const projectSlug = (scan.project?.name || "scan").replace(
    /[^a-zA-Z0-9_-]/g,
    "_",
  );

  if (format === "json") {
    return new NextResponse(JSON.stringify(report, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${projectSlug}-security-report-${timestamp}.json"`,
      },
    });
  }

  if (format === "raw-json") {
    return new NextResponse(JSON.stringify(findings, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${projectSlug}-raw-findings-${timestamp}.json"`,
      },
    });
  }

  if (format === "markdown" || format === "md") {
    return new NextResponse(renderSecurityScanReportMarkdown(report), {
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": `attachment; filename="${projectSlug}-security-report-${timestamp}.md"`,
      },
    });
  }

  if (format === "sarif") {
    const raw: RawFinding[] = findings.map((f) => ({
      scanner: f.scanner as RawFinding["scanner"],
      severity: f.severity as RawFinding["severity"],
      title: f.title,
      description: f.description,
      filePath: f.filePath ?? undefined,
      startLine: f.startLine ?? undefined,
      endLine: f.endLine ?? undefined,
      snippet: f.snippet ?? undefined,
      ruleId: f.ruleId ?? undefined,
      cweId: f.cweId ?? undefined,
      cveId: f.cveId ?? undefined,
      confidence: f.confidence ?? undefined,
      metadata: (f.metadata as Record<string, unknown>) ?? undefined,
      masked: f.masked,
    }));
    const sarif = buildSarif(raw);
    return new NextResponse(JSON.stringify(sarif, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${projectSlug}-results-${timestamp}.sarif.json"`,
      },
    });
  }

  const csvHeader = [
    "Severity",
    "Scanner",
    "Title",
    "Confidence Level",
    "Description",
    "File Path",
    "Function",
    "Start Line",
    "End Line",
    "Rule ID",
    "CWE ID",
    "CVE ID",
    "Confidence",
    "Snippet",
    "Root Cause",
    "Attack Scenario",
    "Proof Of Concept",
    "Fix",
    "Regression Prevention",
  ].join(",");

  const csvRows = report.vulnerabilities.map((v) => {
    const f = findings.find((finding) => finding.id === v.id);
    const detail = v.report;
    return [
      detail.severity,
      v.scanner,
      csvEscape(detail.vulnerabilityName),
      csvEscape(detail.confidenceLevel),
      csvEscape(f?.description || ""),
      csvEscape(detail.affectedFilePath),
      csvEscape(detail.affectedFunction),
      detail.exactLineNumber ?? "",
      f?.endLine ?? "",
      csvEscape(v.ruleId || ""),
      csvEscape(v.cweId || ""),
      csvEscape(v.cveId || ""),
      f?.confidence != null ? f.confidence.toFixed(2) : "",
      csvEscape(detail.vulnerableSourceCode),
      csvEscape(detail.rootCause),
      csvEscape(detail.realWorldAttackScenario),
      csvEscape(detail.proofOfConcept),
      csvEscape(detail.secureFixExplanation),
      csvEscape(detail.regressionPrevention),
    ].join(",");
  });

  const csv = [csvHeader, ...csvRows].join("\n");

  return new NextResponse(csv, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="${projectSlug}-findings-${timestamp}.csv"`,
    },
  });
}

function csvEscape(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}
