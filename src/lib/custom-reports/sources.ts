/**
 * Database / object-storage side of the report tools: loads a scan's data and
 * the lazily-fetched sources (history comparison, compliance mapping, SBOM).
 */
import { prisma } from "@/lib/prisma";
import { canCountResolved, computeScanDelta } from "@/lib/scan-delta";
import { downloadObject } from "@/lib/minio";
import { logger } from "@/lib/logger";
import { loadAllFrameworks } from "@/lib/compliance/pdf-parser";
import { hasDeterministicMapping, mapFindingsDeterministic } from "@/lib/compliance/crosswalk-mapper";
import {
  buildFrameworkReport,
  frameworkSlug,
  toFindingsForMapping,
  type FrameworkReport,
} from "@/lib/compliance/report-run";
import {
  buildReportData,
  type ComplianceSummary,
  type DeltaSummary,
  type DependencySummary,
  type ReportData,
  type ReportSources,
} from "./tools";

const MAX_SBOM_BYTES = 30 * 1024 * 1024;

export async function loadReportData(scanId: string): Promise<ReportData | null> {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      id: true,
      branch: true,
      commitSha: true,
      scanType: true,
      status: true,
      gateResult: true,
      createdAt: true,
      completedAt: true,
      filesScanned: true,
      depsScanned: true,
      project: { select: { name: true, repoUrl: true } },
    },
  });
  if (!scan) return null;
  const findings = await prisma.finding.findMany({
    where: { scanId },
    select: {
      id: true,
      scanner: true,
      severity: true,
      title: true,
      description: true,
      status: true,
      filePath: true,
      startLine: true,
      ruleId: true,
      cweId: true,
      cveId: true,
      confidence: true,
      riskScore: true,
      isNew: true,
      snippet: true,
      metadata: true,
    },
  });
  return buildReportData(
    {
      id: scan.id,
      projectName: scan.project.name,
      repoUrl: scan.project.repoUrl,
      branch: scan.branch,
      commitSha: scan.commitSha,
      scanType: scan.scanType,
      status: scan.status,
      gateResult: scan.gateResult,
      createdAt: scan.createdAt,
      completedAt: scan.completedAt,
      filesScanned: scan.filesScanned,
      depsScanned: scan.depsScanned,
    },
    findings,
  );
}

function summarizeFramework(r: FrameworkReport): ComplianceSummary {
  return {
    framework: r.framework,
    source: r.mappingSource,
    totalControls: r.totalControls,
    impactedControls: r.impactedControls,
    gaps: r.buckets.gapsFound.map((g) => ({
      controlId: g.controlId,
      title: g.title,
      findingCount: g.findingCount,
      criticalHighCount: g.criticalHighCount,
      findingIds: r.findings.filter((f) => f.controls.some((c) => c.controlId === g.controlId)).map((f) => f.id),
    })),
  };
}

function matchesFramework(name: string, wanted: string): boolean {
  const a = frameworkSlug(name);
  const b = frameworkSlug(wanted);
  return a.includes(b) || b.includes(a) || a.replace(/-/g, "").includes(b.replace(/-/g, ""));
}

/** Pepper ScanSnapshot/ScanDelta → the compact summary the tools use. */
export async function loadDelta(scanId: string, scanType: string): Promise<DeltaSummary | null> {
  const delta = await computeScanDelta(scanId);
  if (!delta) return null;
  return {
    baselineScanId: delta.baseline.scanId,
    baselineScanType: delta.baseline.scanType,
    baselineCompletedAt: delta.baseline.completedAt.toISOString(),
    newFindingIds: delta.newFindingIds,
    fixed: delta.result.fixed.map((f) => ({ severity: f.severity, title: f.title, filePath: f.filePath, scanner: f.scanner })),
    fixedComparable: canCountResolved(scanType, delta.baseline.scanType),
    persistingCount: delta.persistingFindingIds.length,
  };
}

export function createReportSources(scanId: string, data: ReportData): ReportSources {
  let delta: Promise<DeltaSummary | null> | null = null;
  let sbom: Promise<DependencySummary> | null = null;
  return {
    delta: () => (delta ??= loadDelta(scanId, data.scan.scanType).catch((e) => {
      logger.warn({ scanId, err: e instanceof Error ? e.message : e }, "Custom report: scan comparison failed");
      return null;
    })),

    async compliance(framework) {
      const scan = await prisma.scan.findUnique({ where: { id: scanId }, select: { scannerProgress: true } });
      const cache = ((scan?.scannerProgress as Record<string, unknown> | null)?._complianceByFramework ?? {}) as Record<string, FrameworkReport>;
      const cached = Object.values(cache).filter((r) => r && typeof r === "object" && "framework" in r);
      const frameworks = loadAllFrameworks();
      const available = [...new Set([...frameworks.map((f) => f.name), ...cached.map((r) => r.framework)])];

      if (!framework) {
        // Latest cached result per framework (the cache is keyed by mode/model too).
        const byName = new Map<string, FrameworkReport>();
        for (const r of cached) byName.set(r.framework, r);
        return {
          available,
          reports: [...byName.values()].slice(0, 5).map(summarizeFramework),
          note: byName.size === 0 ? "No compliance mapping has been run for this scan. Call again with a framework name to map it with the CWE crosswalk." : undefined,
        };
      }
      const hit = cached.filter((r) => matchesFramework(r.framework, framework)).pop();
      if (hit) return { available, reports: [summarizeFramework(hit)] };
      const fw = frameworks.find((f) => matchesFramework(f.name, framework));
      if (!fw) return { available, reports: [], note: `No framework matches "${framework}".` };
      if (!hasDeterministicMapping(fw)) {
        return { available, reports: [], note: `${fw.name} has no deterministic mapping and has not been mapped for this scan; run the compliance report for it first.` };
      }
      const rows = data.findings.map((f) => ({
        id: f.id,
        title: f.title,
        description: f.description,
        severity: f.severity,
        scanner: f.scanner,
        cweId: f.cweId,
        ruleId: f.ruleId,
        filePath: f.filePath,
        startLine: f.startLine,
        status: f.status,
        metadata: f.metadata,
      }));
      const active = rows.filter((r) => r.status !== "FALSE_POSITIVE");
      const report = buildFrameworkReport(fw, active, mapFindingsDeterministic(toFindingsForMapping(active), fw), "crosswalk");
      return { available, reports: [summarizeFramework(report)] };
    },

    dependencies: () => (sbom ??= loadSbomSummary(scanId)),
  };
}

/** Component, ecosystem and license counts from the scan's CycloneDX SBOM. */
export async function loadSbomSummary(scanId: string): Promise<DependencySummary> {
  const artifact = await prisma.scanArtifact.findFirst({
    where: { scanId, type: "SBOM_CYCLONEDX" },
    select: { objectKey: true, size: true },
  });
  if (!artifact || (artifact.size ?? 0) > MAX_SBOM_BYTES) return { sbomAvailable: false };
  try {
    const raw = await downloadObject(artifact.objectKey);
    if (raw.length > MAX_SBOM_BYTES) return { sbomAvailable: false };
    const bom = JSON.parse(raw.toString("utf8")) as {
      components?: Array<{ purl?: string; licenses?: Array<{ license?: { id?: string; name?: string }; expression?: string }> }>;
    };
    const components = bom.components ?? [];
    const ecosystems: Record<string, number> = {};
    const licenses = new Map<string, number>();
    for (const c of components) {
      const eco = c.purl?.match(/^pkg:([^/]+)\//)?.[1] ?? "unknown";
      ecosystems[eco] = (ecosystems[eco] ?? 0) + 1;
      const lic = c.licenses?.map((l) => l.expression ?? l.license?.id ?? l.license?.name).filter(Boolean).join(" OR ") || "unknown";
      licenses.set(lic, (licenses.get(lic) ?? 0) + 1);
    }
    return {
      sbomAvailable: true,
      components: components.length,
      ecosystems,
      licenses: [...licenses.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 12)
        .map(([license, count]) => ({ license, count })),
    };
  } catch (e) {
    logger.warn({ scanId, err: e instanceof Error ? e.message : e }, "Custom report: SBOM unavailable");
    return { sbomAvailable: false };
  }
}
