import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { loadAllFrameworks } from "@/lib/compliance/pdf-parser";
import {
  mapFindingsToControls,
  FindingComplianceResult,
} from "@/lib/compliance/llm-mapper";

/**
 * GET /api/scans/[scanId]/compliance
 *
 * Generates a compliance report by mapping all findings to compliance
 * framework controls using LLM. Results are cached in the scan record.
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

  // Check for cached compliance report in scan metadata
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: { scannerProgress: true, projectId: true },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const scanMeta = (scan.scannerProgress as Record<string, unknown>) || {};
  if (scanMeta._complianceReport) {
    // Return cached report
    return NextResponse.json(scanMeta._complianceReport);
  }

  // Load compliance frameworks from PDFs
  const frameworks = loadAllFrameworks();
  if (frameworks.length === 0) {
    return NextResponse.json(
      {
        error:
          "No compliance frameworks found. Place PDF files in the compliance/ directory.",
      },
      { status: 404 },
    );
  }

  // Load findings for this scan
  const findings = await prisma.finding.findMany({
    where: { scanId },
    select: {
      id: true,
      title: true,
      description: true,
      severity: true,
      scanner: true,
      cweId: true,
      ruleId: true,
      filePath: true,
      startLine: true,
      status: true,
    },
  });

  if (findings.length === 0) {
    return NextResponse.json({
      frameworks: frameworks.map((f) => f.name),
      scanId,
      totalFindings: 0,
      reports: [],
    });
  }

  // Get LLM config from org settings
  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
  });

  const llmConfig = {
    provider: orgSettings?.llmProvider || "openai",
    baseUrl: orgSettings?.llmBaseUrl || "https://api.openai.com/v1",
    apiKey: orgSettings?.llmApiKey || undefined,
    model: orgSettings?.llmModel || "gpt-4o-mini",
  };

  // Map findings to each framework using LLM
  const reports = [];

  for (const framework of frameworks) {
    const mappingResults: FindingComplianceResult[] =
      await mapFindingsToControls(
        findings.map((f) => ({
          id: f.id,
          title: f.title,
          description: f.description,
          severity: f.severity,
          scanner: f.scanner,
          cweId: f.cweId,
          ruleId: f.ruleId,
          filePath: f.filePath,
        })),
        framework,
        llmConfig,
      );

    // Build per-control summary
    const controlCounts = new Map<
      string,
      {
        controlId: string;
        title: string;
        theme: string;
        findingCount: number;
        criticalHighCount: number;
        directCount: number;
        findings: string[];
      }
    >();

    for (const result of mappingResults) {
      const finding = findings.find((f) => f.id === result.findingId);
      for (const control of result.controls) {
        const existing = controlCounts.get(control.controlId) || {
          controlId: control.controlId,
          title: control.title,
          theme: control.theme,
          findingCount: 0,
          criticalHighCount: 0,
          directCount: 0,
          findings: [],
        };
        existing.findingCount++;
        if (finding?.severity === "CRITICAL" || finding?.severity === "HIGH") {
          existing.criticalHighCount++;
        }
        if (control.relevance === "direct") {
          existing.directCount++;
        }
        existing.findings.push(result.findingId);
        controlCounts.set(control.controlId, existing);
      }
    }

    const controlSummary = Array.from(controlCounts.values()).sort(
      (a, b) =>
        b.directCount - a.directCount ||
        b.criticalHighCount - a.criticalHighCount ||
        b.findingCount - a.findingCount,
    );

    // Status counts
    const statusCounts = {
      open: findings.filter((f) => f.status === "OPEN").length,
      inProgress: findings.filter((f) => f.status === "IN_PROGRESS").length,
      resolved: findings.filter((f) => f.status === "RESOLVED").length,
      falsePositive: findings.filter((f) => f.status === "FALSE_POSITIVE")
        .length,
      acceptedRisk: findings.filter((f) => f.status === "ACCEPTED_RISK").length,
    };

    reports.push({
      framework: framework.name,
      fileName: framework.fileName,
      totalControls: framework.controls.length,
      impactedControls: controlCounts.size,
      controlSummary,
      statusCounts,
      findings: mappingResults.map((r) => {
        const f = findings.find((ff) => ff.id === r.findingId);
        return {
          id: r.findingId,
          title: f?.title,
          severity: f?.severity,
          scanner: f?.scanner,
          cweId: f?.cweId,
          filePath: f?.filePath,
          startLine: f?.startLine,
          status: f?.status,
          controls: r.controls,
        };
      }),
    });
  }

  const report = {
    scanId,
    totalFindings: findings.length,
    generatedAt: new Date().toISOString(),
    reports,
  };

  // Cache the report in scannerProgress JSON
  try {
    await prisma.$executeRaw`
      UPDATE "Scan"
      SET "scannerProgress" = COALESCE("scannerProgress", '{}'::jsonb) || ${JSON.stringify({ _complianceReport: report })}::jsonb
      WHERE id = ${scanId}
    `;
  } catch {
    // Cache write failure is non-fatal
  }

  return NextResponse.json(report);
}

/**
 * DELETE /api/scans/[scanId]/compliance
 * Clear cached compliance report (force regeneration on next GET)
 */
export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;

  try {
    await prisma.$executeRaw`
      UPDATE "Scan"
      SET "scannerProgress" = "scannerProgress" - '_complianceReport'
      WHERE id = ${scanId}
    `;
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json(
      { error: "Failed to clear cache" },
      { status: 500 },
    );
  }
}
