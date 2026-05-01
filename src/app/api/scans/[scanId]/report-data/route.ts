import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth-guard";
import { buildSecurityScanReport } from "@/lib/security-report";

/**
 * JSON payload for the HTML assessment report (same logical report as JSON/CSV/Markdown export).
 */
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;

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

  const findingExtras: Record<
    string,
    { confidence: number | null; status: string | null }
  > = {};
  for (const f of findings) {
    findingExtras[f.id] = {
      confidence: f.confidence,
      status: f.status,
    };
  }

  const scannersSeen = [...new Set(findings.map((f) => f.scanner))].sort();

  return NextResponse.json({
    report,
    filesScanned: scan.filesScanned,
    rulesVersion,
    findingExtras,
    scannersSeen,
  });
}
