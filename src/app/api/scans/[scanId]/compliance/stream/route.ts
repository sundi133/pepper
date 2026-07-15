import { NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { loadAllFrameworks } from "@/lib/compliance/pdf-parser";
import { FindingForMapping } from "@/lib/compliance/llm-mapper";
import {
  frameworkSlug,
  runFrameworkMapping,
  type FindingRow,
} from "@/lib/compliance/report-run";
import type { LlmConfig } from "@/lib/llm-gateway";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/scans/[scanId]/compliance/stream?mode=&frameworks=
 *
 * Server-Sent Events stream of the compliance run so the UI can show what the
 * agents are doing in real time. Events:
 *   start     { mode, frameworks: string[], totalFindings }
 *   progress  { framework?, message }        — an agent action
 *   framework <FrameworkReport>              — a completed framework report
 *   done      { scanId, mode, commitSha, totalFindings, generatedAt }
 *   error     { message }
 *
 * Unlike the JSON endpoint this maps frameworks sequentially so the progress
 * log reads as a clear narrative, and it does not write the report cache.
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return new Response("No organization", { status: 403 });

  const url = new URL(req.url);
  const requestedSlugs = (url.searchParams.get("frameworks") || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const mode = url.searchParams.get("mode") === "fast" ? "fast" : "deep";
  const refresh = url.searchParams.get("refresh") === "1";

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: { commitSha: true, scannerProgress: true },
  });
  if (!scan) return new Response("Scan not found", { status: 404 });

  const scanMeta = (scan.scannerProgress as Record<string, unknown>) || {};
  const cache =
    (scanMeta._complianceByFramework as Record<string, unknown>) || {};

  const allFrameworks = loadAllFrameworks();
  const frameworks =
    requestedSlugs.length > 0
      ? allFrameworks.filter((f) =>
          requestedSlugs.includes(frameworkSlug(f.name)),
        )
      : allFrameworks;

  const findings: FindingRow[] = await prisma.finding.findMany({
    where: { scanId, scan: { project: { organizationId: orgId } } },
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

  const findingsForMapping: FindingForMapping[] = findings.map((f) => ({
    id: f.id,
    title: f.title,
    description: f.description,
    severity: f.severity,
    scanner: f.scanner,
    cweId: f.cweId,
    ruleId: f.ruleId,
    filePath: f.filePath,
  }));

  // Lazy LLM config, shared across frameworks.
  let llmConfig: LlmConfig | null = null;
  async function getLlmConfig(): Promise<LlmConfig> {
    if (llmConfig) return llmConfig;
    const orgSettings = await prisma.orgSettings.findUnique({
      where: { organizationId: orgId! },
    });
    llmConfig = {
      provider: orgSettings?.llmProvider || "openai",
      baseUrl: orgSettings?.llmBaseUrl || "https://api.openai.com/v1",
      apiKey: orgSettings?.llmApiKey || undefined,
      model: orgSettings?.llmModel || "gpt-4o-mini",
    };
    return llmConfig;
  }
  const canUseLlm =
    mode === "deep"
      ? await (async () => {
          const cfg = await getLlmConfig();
          return cfg.provider === "ollama" || !!cfg.apiKey;
        })()
      : false;

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: string, data: unknown) => {
        controller.enqueue(
          encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`),
        );
      };

      const updatedCache: Record<string, unknown> = { ...cache };
      let cacheDirty = false;

      try {
        send("start", {
          mode,
          frameworks: frameworks.map((f) => f.name),
          totalFindings: findings.length,
        });

        for (const framework of frameworks) {
          const cacheKey = `${frameworkSlug(framework.name)}::${mode}`;

          if (!refresh && cache[cacheKey]) {
            send("progress", {
              framework: framework.name,
              message: `${framework.name}: loaded from cache`,
            });
            send("framework", cache[cacheKey]);
            continue;
          }

          send("progress", {
            framework: framework.name,
            message: `Starting ${framework.name} (${framework.controls.length} controls)`,
          });

          const { report } = await runFrameworkMapping({
            framework,
            findings,
            findingsForMapping,
            mode,
            canUseLlm,
            getLlmConfig,
            onProgress: (message) =>
              send("progress", { framework: framework.name, message }),
          });

          const gaps = report.buckets.gapsFound.length;
          send("progress", {
            framework: framework.name,
            message: `${framework.name} done — ${gaps} control(s) with gaps, ${report.impactedControls}/${report.totalControls} impacted`,
          });
          send("framework", report);
          updatedCache[cacheKey] = report;
          cacheDirty = true;
        }

        if (cacheDirty) {
          try {
            await prisma.$executeRaw`
              UPDATE "Scan"
              SET "scannerProgress" = COALESCE("scannerProgress", '{}'::jsonb) || ${JSON.stringify(
                { _complianceByFramework: updatedCache },
              )}::jsonb
              WHERE id = ${scanId}
            `;
          } catch {
            // Cache write failure is non-fatal.
          }
        }

        send("done", {
          scanId,
          mode,
          commitSha: scan.commitSha || null,
          totalFindings: findings.length,
          generatedAt: new Date().toISOString(),
        });
      } catch (err) {
        send("error", {
          message: err instanceof Error ? err.message : "Streaming failed",
        });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
