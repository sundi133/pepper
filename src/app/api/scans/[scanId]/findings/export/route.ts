import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth-guard";

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
    select: { id: true, project: { select: { name: true } } },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const findings = await prisma.finding.findMany({
    where: { scanId },
    orderBy: [{ severity: "asc" }, { scanner: "asc" }, { filePath: "asc" }],
  });

  const timestamp = new Date().toISOString().slice(0, 10);
  const projectSlug = (scan.project?.name || "scan").replace(
    /[^a-zA-Z0-9_-]/g,
    "_",
  );

  if (format === "json") {
    return new NextResponse(JSON.stringify(findings, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${projectSlug}-findings-${timestamp}.json"`,
      },
    });
  }

  const csvHeader = [
    "Severity",
    "Scanner",
    "Title",
    "Description",
    "File Path",
    "Start Line",
    "End Line",
    "Rule ID",
    "CWE ID",
    "CVE ID",
    "Confidence",
    "Snippet",
  ].join(",");

  const csvRows = findings.map((f) =>
    [
      f.severity,
      f.scanner,
      csvEscape(f.title),
      csvEscape(f.description),
      csvEscape(f.filePath || ""),
      f.startLine ?? "",
      f.endLine ?? "",
      csvEscape(f.ruleId || ""),
      csvEscape(f.cweId || ""),
      csvEscape(f.cveId || ""),
      f.confidence != null ? f.confidence.toFixed(2) : "",
      csvEscape(f.snippet || ""),
    ].join(","),
  );

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
