import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  loadAllFrameworks,
  ComplianceFramework,
} from "@/lib/compliance/pdf-parser";
import {
  mapFindingsToControls,
  FindingComplianceResult,
  FindingForMapping,
} from "@/lib/compliance/llm-mapper";
import {
  mapFindingsDeterministic,
  hasDeterministicMapping,
  controlCoverage,
  summarizeCoverage,
} from "@/lib/compliance/crosswalk-mapper";
import { mapFindingsAgentic } from "@/lib/compliance/agentic-mapper";

/** Stable slug for a framework, used in ?frameworks= selection and caching. */
function frameworkSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

type FindingRow = {
  id: string;
  title: string;
  description: string;
  severity: string;
  scanner: string;
  cweId: string | null;
  ruleId: string | null;
  filePath: string | null;
  startLine: number | null;
  status: string;
};

/**
 * Build a single framework's report from its finding→control mappings.
 * Adds the three-bucket coverage view (gaps found / no issues detected /
 * not covered by SAST) on top of the legacy controlSummary shape.
 */
function buildFrameworkReport(
  framework: ComplianceFramework,
  findings: FindingRow[],
  mappingResults: FindingComplianceResult[],
  source: "agentic" | "crosswalk" | "llm",
) {
  const findingsById = new Map(findings.map((f) => [f.id, f]));

  // Per-control aggregation from the mappings.
  type ControlAgg = {
    controlId: string;
    title: string;
    theme: string;
    findingCount: number;
    criticalHighCount: number;
    directCount: number;
    findings: string[];
  };
  const controlCounts = new Map<string, ControlAgg>();

  for (const result of mappingResults) {
    const finding = findingsById.get(result.findingId);
    for (const control of result.controls) {
      const existing =
        controlCounts.get(control.controlId) ||
        ({
          controlId: control.controlId,
          title: control.title,
          theme: control.theme,
          findingCount: 0,
          criticalHighCount: 0,
          directCount: 0,
          findings: [],
        } satisfies ControlAgg);
      existing.findingCount++;
      if (finding?.severity === "CRITICAL" || finding?.severity === "HIGH") {
        existing.criticalHighCount++;
      }
      if (control.relevance === "direct") existing.directCount++;
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

  // Three-bucket coverage view over the FULL control catalog (finding-independent
  // scope statement — never infer "compliant" from "no findings").
  const gapsFound = [];
  const noIssuesDetected = [];
  const notCovered = [];

  for (const control of framework.controls) {
    const coverage = controlCoverage(control);
    const agg = controlCounts.get(control.controlId);
    const findingCount = agg?.findingCount ?? 0;
    const criticalHighCount = agg?.criticalHighCount ?? 0;
    const entry = {
      controlId: control.controlId,
      title: control.title,
      theme: control.theme,
      coverage,
      findingCount,
      criticalHighCount,
    };
    if (findingCount > 0) {
      gapsFound.push(entry);
    } else if (coverage === "assessable") {
      noIssuesDetected.push(entry);
    } else {
      notCovered.push({
        ...entry,
        reason:
          coverage === "not-assessable"
            ? "Not assessable by SAST — requires process, physical, or organizational evidence."
            : "Partially assessable by SAST; no supporting evidence found in code.",
      });
    }
  }

  gapsFound.sort(
    (a, b) => b.criticalHighCount - a.criticalHighCount || b.findingCount - a.findingCount,
  );

  const statusCounts = {
    open: findings.filter((f) => f.status === "OPEN").length,
    inProgress: findings.filter((f) => f.status === "IN_PROGRESS").length,
    resolved: findings.filter((f) => f.status === "RESOLVED").length,
    falsePositive: findings.filter((f) => f.status === "FALSE_POSITIVE").length,
    acceptedRisk: findings.filter((f) => f.status === "ACCEPTED_RISK").length,
  };

  return {
    framework: framework.name,
    slug: frameworkSlug(framework.name),
    version: framework.version || null,
    fileName: framework.fileName,
    mappingSource: source,
    totalControls: framework.controls.length,
    impactedControls: controlCounts.size,
    coverage: summarizeCoverage(framework),
    buckets: { gapsFound, noIssuesDetected, notCovered },
    controlSummary,
    statusCounts,
    findings: mappingResults.map((r) => {
      const f = findingsById.get(r.findingId);
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
  };
}

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

  const reports = [];
  const updatedCache: Record<string, unknown> = { ...cache };
  let cacheDirty = false;

  // Decide once whether the org's configured LLM can actually be used for the
  // agentic ("deep") path. Local Ollama needs no key; hosted providers do.
  async function llmUsable(): Promise<boolean> {
    const cfg = await getLlmConfig();
    return cfg.provider === "ollama" || !!cfg.apiKey;
  }
  const canUseLlm = mode === "deep" ? await llmUsable() : false;

  for (const framework of frameworks) {
    const slug = frameworkSlug(framework.name);
    const cacheKey = `${slug}::${mode}`;

    if (!refresh && cache[cacheKey]) {
      reports.push(cache[cacheKey]);
      continue;
    }

    const deterministic = hasDeterministicMapping(framework);
    let mappingResults: FindingComplianceResult[];
    let source: "agentic" | "crosswalk" | "llm";

    if (findings.length === 0) {
      mappingResults = [];
      source = mode === "deep" && canUseLlm ? "agentic" : deterministic ? "crosswalk" : "llm";
    } else if (mode === "deep" && canUseLlm) {
      // Agentic engine: LLM-driven, grounded by the crosswalk, self-verifying.
      const cfg = await getLlmConfig();
      mappingResults = await mapFindingsAgentic(
        findingsForMapping,
        framework,
        cfg,
      );
      source = "agentic";
    } else if (deterministic) {
      mappingResults = mapFindingsDeterministic(findingsForMapping, framework);
      source = "crosswalk";
    } else {
      const cfg = await getLlmConfig();
      mappingResults = await mapFindingsToControls(
        findingsForMapping,
        framework,
        cfg,
      );
      source = "llm";
    }

    const report = buildFrameworkReport(
      framework,
      findings,
      mappingResults,
      source,
    );
    reports.push(report);
    updatedCache[cacheKey] = report;
    cacheDirty = true;
  }

  const response = {
    scanId,
    commitSha: scan.commitSha || null,
    mode,
    totalFindings: findings.length,
    generatedAt: new Date().toISOString(),
    availableFrameworks: allFrameworks.map((f) => ({
      name: f.name,
      slug: frameworkSlug(f.name),
      version: f.version || null,
    })),
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
