/**
 * Compliance results as CSV: one row per control (the audit matrix) or one
 * row per finding-to-control mapping. Built from the cached per-framework
 * reports plus the framework catalogs (for ASVS levels and CIS sections).
 */
import type { ComplianceFramework } from "@/lib/compliance/pdf-parser";
import type { ComplianceExportInput, ComplianceFrameworkReport } from "./compliance-report";

/**
 * RFC 4180 quoting, plus a leading `'` on values a spreadsheet would run as a
 * formula (finding titles and file paths come from scanned code).
 */
export function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  let s = typeof value === "string" ? value : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const line = (cells: unknown[]) => cells.map(csvCell).join(",");

const STATUS = {
  gap: "Gap found",
  clear: "No issues detected",
  notCovered: "Not covered by code scanning",
} as const;

type Catalog = Map<string, ComplianceFramework>;

function controlMeta(catalog: Catalog, framework: string, controlId: string) {
  const c = catalog.get(framework)?.controls.find((x) => x.controlId === controlId);
  return {
    theme: c?.theme ?? "",
    levels: c?.levels?.length ? c.levels.map((l) => `L${l}`).join(" ") : "",
    manual: c?.assessment === "manual",
  };
}

function controlRows(r: ComplianceFrameworkReport, catalog: Catalog): string[] {
  const mapped = new Map<string, string[]>();
  for (const f of r.findings) {
    for (const c of f.controls) mapped.set(c.controlId, [...(mapped.get(c.controlId) ?? []), f.id]);
  }
  const b = r.buckets;
  const entries = b
    ? [
        ...b.gapsFound.map((e) => ({ e, status: STATUS.gap })),
        ...b.noIssuesDetected.map((e) => ({ e, status: STATUS.clear })),
        ...b.notCovered.map((e) => ({ e, status: STATUS.notCovered })),
      ]
    : [];
  return entries.map(({ e, status }) => {
    const meta = controlMeta(catalog, r.framework, e.controlId);
    return line([
      r.framework,
      r.version ?? "",
      e.controlId,
      e.title,
      e.theme || meta.theme,
      meta.levels,
      e.coverage ?? "",
      status,
      e.findingCount,
      e.criticalHighCount,
      (mapped.get(e.controlId) ?? []).join(" "),
    ]);
  });
}

function findingRows(r: ComplianceFrameworkReport): string[] {
  const rows: string[] = [];
  for (const f of r.findings) {
    for (const c of f.controls) {
      rows.push(
        line([
          r.framework,
          r.version ?? "",
          c.controlId,
          c.title,
          c.relevance ?? "",
          f.id,
          f.title ?? "",
          f.severity ?? "",
          f.filePath ?? "",
          f.startLine ?? "",
          f.status ?? "",
          c.reasoning ?? "",
        ]),
      );
    }
  }
  return rows;
}

export const CONTROL_COLUMNS = [
  "framework",
  "version",
  "controlId",
  "control",
  "section",
  "levels",
  "coverage",
  "status",
  "findings",
  "criticalHigh",
  "findingIds",
];

export const FINDING_COLUMNS = [
  "framework",
  "version",
  "controlId",
  "control",
  "relevance",
  "findingId",
  "finding",
  "severity",
  "file",
  "line",
  "status",
  "reasoning",
];

export function buildComplianceCsv(
  input: ComplianceExportInput,
  frameworks: ComplianceFramework[],
  rows: "controls" | "findings",
): string {
  const catalog: Catalog = new Map(frameworks.map((f) => [f.name, f]));
  const header = line(rows === "controls" ? CONTROL_COLUMNS : FINDING_COLUMNS);
  const body = input.reports.flatMap((r) => (rows === "controls" ? controlRows(r, catalog) : findingRows(r)));
  return [header, ...body].join("\r\n") + "\r\n";
}
