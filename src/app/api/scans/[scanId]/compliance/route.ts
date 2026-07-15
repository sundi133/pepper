import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { loadAllFrameworks } from "@/lib/compliance/pdf-parser";
import { hasDeterministicMapping } from "@/lib/compliance/crosswalk-mapper";
import { FindingForMapping } from "@/lib/compliance/llm-mapper";
import {
  frameworkSlug,
  runFrameworkMapping,
  type FindingRow,
} from "@/lib/compliance/report-run";

/**
 * GET /api/scans/[scanId]/compliance
 *
 * Maps findings to compliance framework controls. Frameworks carrying a
 * deterministic CWE crosswalk are mapped without an LLM (reproducible);
 * others fall back to the LLM mapper. Per-framework results are cached.
 *
 * Query params:
 *   ?frameworks=owasp-top-10,pci-dss   Only generate these framework slugs.
 *   ?refresh=1                         Ignore cache and recompute.
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
  const requestedSlugs = (url.searchParams.get("frameworks") || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const refresh = url.searchParams.get("refresh") === "1";
  // "deep" (default) = agentic LLM mapping with grounding + self-verification.
  // "fast" = deterministic CWE crosswalk only (no LLM).
  const mode = url.searchParams.get("mode") === "fast" ? "fast" : "deep";

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: { scannerProgress: true, commitSha: true },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const allFrameworks = loadAllFrameworks();
  if (allFrameworks.length === 0) {
    return NextResponse.json(
      {
        error:
          "No compliance frameworks found. Place framework JSON/PDF files in the compliance/ directory.",
      },
      { status: 404 },
    );
  }

  const available = allFrameworks.map((f) => ({
    name: f.name,
    slug: frameworkSlug(f.name),
    version: f.version || null,
    controls: f.controls.length,
    deterministic: hasDeterministicMapping(f),
  }));

  // Lightweight listing: return the framework catalog without running any
  // mapping. Powers the "pick then run" selector in the UI.
  if (url.searchParams.get("list") === "1") {
    return NextResponse.json({ scanId, availableFrameworks: available });
  }

  // Select the requested frameworks (default: all).
  const frameworks =
    requestedSlugs.length > 0
      ? allFrameworks.filter((f) => requestedSlugs.includes(frameworkSlug(f.name)))
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

  const scanMeta = (scan.scannerProgress as Record<string, unknown>) || {};
  const cache =
    (scanMeta._complianceByFramework as Record<string, unknown>) || {};

  // Lazily resolve LLM config only if a non-deterministic framework is selected.
  let llmConfig: {
    provider: string;
    baseUrl: string;
    apiKey: string | undefined;
    model: string;
  } | null = null;
  async function getLlmConfig() {
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

  // Decide once whether the org's configured LLM can actually be used for the
  // agentic ("deep") path. Local Ollama needs no key; hosted providers do.
  // Pre-resolving here also warms getLlmConfig()'s memo before the concurrent
  // map below, so the parallel framework tasks don't race on it.
  async function llmUsable(): Promise<boolean> {
    const cfg = await getLlmConfig();
    return cfg.provider === "ollama" || !!cfg.apiKey;
  }
  const canUseLlm = mode === "deep" ? await llmUsable() : false;

  // Frameworks are independent, so map them concurrently instead of
  // one-after-another (major speedup). Each task returns its report plus the
  // cache key; the shared cache is assembled afterwards to avoid races.
  const perFramework = await Promise.all(
    frameworks.map(async (framework) => {
      const slug = frameworkSlug(framework.name);
      const cacheKey = `${slug}::${mode}`;

      if (!refresh && cache[cacheKey]) {
        return { cacheKey, report: cache[cacheKey], cached: true };
      }

      const { report } = await runFrameworkMapping({
        framework,
        findings,
        findingsForMapping,
        mode,
        canUseLlm,
        getLlmConfig,
      });
      return { cacheKey, report, cached: false };
    }),
  );

  const reports = perFramework.map((r) => r.report);
  const updatedCache: Record<string, unknown> = { ...cache };
  let cacheDirty = false;
  for (const r of perFramework) {
    if (!r.cached) {
      updatedCache[r.cacheKey] = r.report;
      cacheDirty = true;
    }
  }

  const response = {
    scanId,
    commitSha: scan.commitSha || null,
    mode,
    totalFindings: findings.length,
    generatedAt: new Date().toISOString(),
    availableFrameworks: available,
    reports,
  };

  // Persist per-framework cache (best-effort).
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

  return NextResponse.json(response);
}

/**
 * DELETE /api/scans/[scanId]/compliance
 * Clear cached compliance reports (force regeneration on next GET).
 */
export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId)
    return NextResponse.json({ error: "No organization" }, { status: 403 });

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: { id: true },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  try {
    await prisma.$executeRaw`
      UPDATE "Scan"
      SET "scannerProgress" = ("scannerProgress" - '_complianceReport') - '_complianceByFramework'
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
