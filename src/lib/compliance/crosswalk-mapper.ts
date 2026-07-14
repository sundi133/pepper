/**
 * Deterministic compliance mapping engine.
 *
 * Maps findings → framework controls using published CWE crosswalks and
 * activity-level rules baked into the framework control catalog. No LLM, so
 * the same scan always produces the same mapping — the reproducibility
 * auditors require.
 *
 * This is Tier 1 of the two-tier engine (see docs/COMPLIANCE_REPORTING_SPEC.md).
 * Frameworks whose controls carry `cweMapping` / `appliesTo` are mapped here;
 * everything else falls back to the LLM mapper.
 */
import { ComplianceFramework, ComplianceControl, Coverage } from "./pdf-parser";
import type {
  FindingForMapping,
  FindingComplianceResult,
  ControlMapping,
} from "./llm-mapper";

/** Normalize a raw CWE id ("79", "cwe-79", "CWE-79 ") → "CWE-79". */
export function normalizeCwe(raw?: string | null): string | null {
  if (!raw) return null;
  const m = String(raw)
    .trim()
    .toUpperCase()
    .match(/(\d+)/);
  return m ? `CWE-${m[1]}` : null;
}

/**
 * True when this framework carries deterministic mapping data and should be
 * handled by the crosswalk engine rather than the LLM.
 */
export function hasDeterministicMapping(framework: ComplianceFramework): boolean {
  return framework.controls.some(
    (c) => (c.cweMapping && c.cweMapping.length > 0) || c.appliesTo,
  );
}

/** Default coverage class for a control when not explicitly set. */
export function controlCoverage(control: ComplianceControl): Coverage {
  if (control.coverage) return control.coverage;
  if (control.cweMapping && control.cweMapping.length > 0) return "assessable";
  if (control.appliesTo) return "assessable";
  return "not-assessable";
}

/**
 * Map findings to controls deterministically.
 *
 * - A finding whose CWE is listed in a control's `cweMapping` → "direct".
 * - A finding whose scanner matches a control's `appliesTo` → "supporting".
 * Direct wins over supporting for the same control.
 */
export function mapFindingsDeterministic(
  findings: FindingForMapping[],
  framework: ComplianceFramework,
): FindingComplianceResult[] {
  // Build a CWE → controls[] index once per framework.
  const cweIndex = new Map<string, ComplianceControl[]>();
  const activityControls: ComplianceControl[] = [];

  for (const control of framework.controls) {
    for (const cwe of control.cweMapping || []) {
      const norm = normalizeCwe(cwe);
      if (!norm) continue;
      const list = cweIndex.get(norm) || [];
      list.push(control);
      cweIndex.set(norm, list);
    }
    if (control.appliesTo) activityControls.push(control);
  }

  return findings.map((finding) => {
    const byControlId = new Map<string, ControlMapping>();
    const cwe = normalizeCwe(finding.cweId);

    // Direct: CWE crosswalk.
    if (cwe) {
      for (const control of cweIndex.get(cwe) || []) {
        byControlId.set(control.controlId, {
          controlId: control.controlId,
          title: control.title,
          theme: control.theme || "Unknown",
          relevance: "direct",
          reasoning: `${cwe} maps directly to ${control.controlId} (${control.title}) per the ${framework.name} crosswalk.`,
        });
      }
    }

    // Supporting: activity-level evidence (scanner-scoped).
    for (const control of activityControls) {
      const scanners = control.appliesTo?.scanners;
      const scannerMatches =
        !scanners || scanners.length === 0 || scanners.includes(finding.scanner);
      if (!scannerMatches) continue;
      if (byControlId.has(control.controlId)) continue; // direct already wins
      byControlId.set(control.controlId, {
        controlId: control.controlId,
        title: control.title,
        theme: control.theme || "Unknown",
        relevance: "supporting",
        reasoning: `A ${finding.scanner} finding is evidence toward ${control.controlId} (${control.title}).`,
      });
    }

    return { findingId: finding.id, controls: Array.from(byControlId.values()) };
  });
}

export interface CoverageSummary {
  assessable: number;
  partial: number;
  notAssessable: number;
}

/** Count controls by coverage class for the report header. */
export function summarizeCoverage(
  framework: ComplianceFramework,
): CoverageSummary {
  const summary: CoverageSummary = {
    assessable: 0,
    partial: 0,
    notAssessable: 0,
  };
  for (const control of framework.controls) {
    const cov = controlCoverage(control);
    if (cov === "assessable") summary.assessable++;
    else if (cov === "partial") summary.partial++;
    else summary.notAssessable++;
  }
  return summary;
}
