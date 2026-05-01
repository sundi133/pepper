import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, requireRole } from "@/lib/auth-guard";
import { createLlmClient, generateLlmText } from "@/lib/llm-gateway";
import { ASSESSMENT_REPORT_SYSTEM_PROMPT } from "@/lib/assessment-report-prompt";
import { buildAssessmentReportUserPayload } from "@/lib/assessment-report-input";
import { logger } from "@/lib/logger";

export const maxDuration = 300;

type AssessmentReportCache = {
  markdown: string;
  generatedAt: string;
  model?: string;
};

function getCachedReport(
  scannerProgress: unknown,
): AssessmentReportCache | null {
  if (
    !scannerProgress ||
    typeof scannerProgress !== "object" ||
    Array.isArray(scannerProgress)
  ) {
    return null;
  }
  const ar = (scannerProgress as Record<string, unknown>).assessmentReport;
  if (!ar || typeof ar !== "object" || Array.isArray(ar)) return null;
  const markdown = (ar as Record<string, unknown>).markdown;
  const generatedAt = (ar as Record<string, unknown>).generatedAt;
  if (typeof markdown !== "string" || typeof generatedAt !== "string") {
    return null;
  }
  const model = (ar as Record<string, unknown>).model;
  return {
    markdown,
    generatedAt,
    model: typeof model === "string" ? model : undefined,
  };
}

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;

  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      id: true,
      status: true,
      scannerProgress: true,
      project: { select: { organizationId: true } },
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const gate = await requireRole(scan.project.organizationId, "VIEWER");
  if ("error" in gate) return gate.error;

  const cached = getCachedReport(scan.scannerProgress);
  return NextResponse.json({
    markdown: cached?.markdown ?? null,
    generatedAt: cached?.generatedAt ?? null,
    model: cached?.model ?? null,
    scanStatus: scan.status,
  });
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;
  const body = await req.json().catch(() => ({}));
  const regenerate = Boolean((body as { regenerate?: boolean }).regenerate);

  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      id: true,
      status: true,
      scannerProgress: true,
      completedAt: true,
      filesScanned: true,
      project: {
        select: {
          name: true,
          organizationId: true,
        },
      },
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const gate = await requireRole(scan.project.organizationId, "DEVELOPER");
  if ("error" in gate) return gate.error;

  if (scan.status !== "COMPLETED") {
    return NextResponse.json(
      { error: "Assessment report can only be generated for completed scans." },
      { status: 400 },
    );
  }

  const cached = getCachedReport(scan.scannerProgress);
  if (cached && !regenerate) {
    return NextResponse.json({
      markdown: cached.markdown,
      generatedAt: cached.generatedAt,
      model: cached.model ?? null,
      cached: true,
    });
  }

  const orgSettings = await prisma.orgSettings.findUnique({
    where: { organizationId: scan.project.organizationId },
  });

  if (!orgSettings?.enableLlmSast) {
    return NextResponse.json(
      {
        error:
          "Enable LLM SAST in Organization Settings to generate the assessment report.",
      },
      { status: 400 },
    );
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
      : null;

  const userPayload = buildAssessmentReportUserPayload({
    projectName: scan.project.name || "Project",
    scanId,
    scanStatus: scan.status,
    completedAt: scan.completedAt?.toISOString() ?? null,
    filesScanned: scan.filesScanned,
    architectureOverview,
    findings,
  });

  const maxTokens = parseInt(
    process.env.ASSESSMENT_REPORT_MAX_TOKENS || "12000",
    10,
  );

  const client = createLlmClient({
    provider: orgSettings.llmProvider || "openai",
    baseUrl: orgSettings.llmBaseUrl || "https://api.openai.com/v1",
    apiKey: orgSettings.llmApiKey || undefined,
    model: orgSettings.llmModel || "gpt-4o-mini",
  });

  try {
    const markdown = await generateLlmText(
      client,
      orgSettings.llmModel || "gpt-4o-mini",
      ASSESSMENT_REPORT_SYSTEM_PROMPT,
      userPayload,
      { temperature: 0.15, maxTokens },
    );

    if (!markdown || markdown.length < 80) {
      logger.warn({ scanId, len: markdown?.length }, "Assessment report empty");
      return NextResponse.json(
        { error: "Report generation returned empty output. Retry or check LLM settings." },
        { status: 502 },
      );
    }

    const generatedAt = new Date().toISOString();
    const modelUsed = orgSettings.llmModel || "gpt-4o-mini";

    const nextProgress = {
      ...progress,
      assessmentReport: {
        markdown,
        generatedAt,
        model: modelUsed,
      },
    };

    await prisma.scan.update({
      where: { id: scanId },
      data: { scannerProgress: nextProgress },
    });

    return NextResponse.json({
      markdown,
      generatedAt,
      model: modelUsed,
      cached: false,
    });
  } catch (err) {
    logger.error({ err, scanId }, "Assessment report generation failed");
    return NextResponse.json(
      {
        error:
          err instanceof Error ? err.message : "Report generation failed.",
      },
      { status: 502 },
    );
  }
}
