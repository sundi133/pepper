/**
 * Shared compliance report logic used by both the JSON endpoint
 * (route.ts) and the streaming SSE endpoint (stream/route.ts).
 *
 * - buildFrameworkReport: turn finding→control mappings into a framework report
 *   with the three-bucket coverage view.
 * - runFrameworkMapping: pick the engine (agentic / deterministic / llm) for a
 *   framework and return its report, forwarding progress via onProgress.
 */
import { ComplianceFramework } from "./pdf-parser";
import {
  mapFindingsToControls,
  FindingComplianceResult,
  FindingForMapping,
} from "./llm-mapper";
import {
  mapFindingsDeterministic,
  hasDeterministicMapping,
  controlCoverage,
  summarizeCoverage,
} from "./crosswalk-mapper";
import { mapFindingsAgentic } from "./agentic-mapper";
import type { LlmConfig } from "@/lib/llm-gateway";

export type MappingSource = "agentic" | "crosswalk" | "llm";

/** Stable slug for a framework, used in ?frameworks= selection and caching. */
export function frameworkSlug(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

export type FindingRow = {
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

export function buildFrameworkReport(
  framework: ComplianceFramework,
  findings: FindingRow[],
  mappingResults: FindingComplianceResult[],
  source: MappingSource,
) {
  const findingsById = new Map(findings.map((f) => [f.id, f]));

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
    (a, b) =>
      b.criticalHighCount - a.criticalHighCount || b.findingCount - a.findingCount,
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

export type FrameworkReport = ReturnType<typeof buildFrameworkReport>;

/**
 * Map one framework with the appropriate engine and build its report.
 * onProgress receives agent-action messages (surfaced by the SSE endpoint).
 */
export async function runFrameworkMapping(opts: {
  framework: ComplianceFramework;
  findings: FindingRow[];
  findingsForMapping: FindingForMapping[];
  mode: "deep" | "fast";
  canUseLlm: boolean;
  getLlmConfig: () => Promise<LlmConfig>;
  onProgress?: (message: string) => void;
}): Promise<{ report: FrameworkReport; source: MappingSource }> {
  const {
    framework,
    findings,
    findingsForMapping,
    mode,
    canUseLlm,
    getLlmConfig,
    onProgress,
  } = opts;

  const deterministic = hasDeterministicMapping(framework);
  let mappingResults: FindingComplianceResult[];
  let source: MappingSource;

  if (findings.length === 0) {
    mappingResults = [];
    source =
      mode === "deep" && canUseLlm
        ? "agentic"
        : deterministic
          ? "crosswalk"
          : "llm";
  } else if (mode === "deep" && canUseLlm) {
    const cfg = await getLlmConfig();
    mappingResults = await mapFindingsAgentic(
      findingsForMapping,
      framework,
      cfg,
      onProgress,
    );
    source = "agentic";
  } else if (deterministic) {
    onProgress?.(`${framework.name}: deterministic CWE crosswalk (instant)`);
    mappingResults = mapFindingsDeterministic(findingsForMapping, framework);
    source = "crosswalk";
  } else {
    const cfg = await getLlmConfig();
    mappingResults = await mapFindingsToControls(
      findingsForMapping,
      framework,
      cfg,
      onProgress,
    );
    source = "llm";
  }

  const report = buildFrameworkReport(framework, findings, mappingResults, source);
  return { report, source };
}
