/**
 * The report agent's tools: read-only, bounded views of one scan's real data.
 * The model never sees raw rows in bulk — it asks for summaries, filtered
 * pages and single findings, and every finding it can see carries a short
 * reference (F1, F2, …) that the grounding check later verifies.
 *
 * Pure over a loaded ReportData; the few lookups that need the database or
 * object storage (history, compliance, SBOM) come in through ReportSources so
 * they can be replaced in tests.
 */
import { findingCategory } from "@/lib/reports/executive-report";
import { severityRank } from "@/lib/reports/report-html";

export interface ReportFinding {
  /** Short citation handle, stable for the whole report ("F12"). */
  ref: string;
  id: string;
  scanner: string;
  severity: string;
  title: string;
  description: string;
  status: string;
  filePath: string | null;
  startLine: number | null;
  ruleId: string | null;
  cweId: string | null;
  cveId: string | null;
  confidence: number | null;
  riskScore: number | null;
  isNew: boolean | null;
  snippet: string | null;
  metadata: unknown;
}

export interface ReportScan {
  id: string;
  projectName: string;
  repoUrl: string | null;
  branch: string | null;
  commitSha: string | null;
  scanType: string;
  status: string;
  gateResult: string;
  createdAt: Date;
  completedAt: Date | null;
  filesScanned: number;
  depsScanned: number;
}

export interface ReportData {
  scan: ReportScan;
  /** Every finding of the scan (false positives included), in ref order. */
  findings: ReportFinding[];
  byRef: Map<string, ReportFinding>;
  byId: Map<string, ReportFinding>;
}

export interface DeltaSummary {
  baselineScanId: string;
  baselineScanType: string;
  baselineCompletedAt: string;
  newFindingIds: string[];
  fixed: Array<{ severity: string; title: string; filePath: string | null; scanner: string }>;
  fixedComparable: boolean;
  persistingCount: number;
}

export interface ComplianceSummary {
  framework: string;
  source: string;
  totalControls: number;
  impactedControls: number;
  gaps: Array<{ controlId: string; title: string; findingCount: number; criticalHighCount: number; findingIds: string[] }>;
}

export interface DependencySummary {
  sbomAvailable: boolean;
  components?: number;
  ecosystems?: Record<string, number>;
  licenses?: Array<{ license: string; count: number }>;
}

export interface ReportSources {
  delta: () => Promise<DeltaSummary | null>;
  compliance: (framework: string | null) => Promise<{ available: string[]; reports: ComplianceSummary[]; note?: string }>;
  dependencies: () => Promise<DependencySummary>;
}

export interface ToolCall {
  tool: string;
  args?: Record<string, unknown>;
}

const LIST_MAX = 50;
const AGG_MAX = 25;
const DESCRIPTION_CHARS = 1500;
const SNIPPET_CHARS = 600;
const SUPPRESSED = new Set(["FALSE_POSITIVE"]);
const ACTIVE = new Set(["OPEN", "IN_PROGRESS"]);
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

/** Tool descriptions, as shown to the model. */
export const TOOL_CATALOG = [
  {
    name: "get_scan_summary",
    args: "{}",
    description:
      "Repository, branch, commit, scan type/status/dates, build gate, files and dependencies scanned, severity counts (total and open), status counts, counts per scanner and top risk categories. False positives are excluded from counts.",
  },
  {
    name: "list_findings",
    args: '{"severity"?: ["CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO"], "scanner"?: [string], "cwe"?: "CWE-79", "category"?: string, "status"?: ["OPEN"|"IN_PROGRESS"|"RESOLVED"|"ACCEPTED_RISK"|"FALSE_POSITIVE"], "includeFalsePositives"?: boolean, "newOnly"?: boolean, "fileContains"?: string, "sort"?: "severity"|"risk", "limit"?: number (max 50), "offset"?: number}',
    description:
      "A page of findings matching the filters (false positives excluded unless asked), most severe first, with total matches. Each item has its ref (F1, F2…) — cite findings ONLY by these refs.",
  },
  {
    name: "get_finding",
    args: '{"refs": ["F1", …] (max 5)}',
    description: "Full details for up to 5 findings: description, location, rule/CWE/CVE, code snippet (secrets masked), package data, remediation notes.",
  },
  {
    name: "aggregate_findings",
    args: '{"groupBy": "severity"|"scanner"|"cwe"|"category"|"file"|"status"|"rule"|"package", plus any list_findings filter, "top"?: number (max 25)}',
    description: "Counts of matching findings grouped by a field, with the critical+high count per group. Use this instead of listing many findings.",
  },
  {
    name: "compare_with_previous_scan",
    args: "{}",
    description: "Changes since the repository's previous scan: new findings (with refs), fixed findings (no longer detected — they have no ref), counts by severity.",
  },
  {
    name: "get_compliance_mapping",
    args: '{"framework"?: "OWASP Top 10" | "PCI DSS" | "ISO 27001" | "SOC 2" | …}',
    description: "Compliance framework controls affected by this scan's findings (cached compliance results, or the deterministic CWE crosswalk). Without a framework, returns the frameworks available.",
  },
  {
    name: "get_dependency_summary",
    args: "{}",
    description: "Dependencies scanned, SBOM component counts by ecosystem and top licenses, and vulnerable / license-flagged packages from dependency findings.",
  },
] as const;

export const TOOL_NAMES: ReadonlySet<string> = new Set(TOOL_CATALOG.map((t) => t.name));

// ─── Data preparation ─────────────────────────────────────────────────

/** Order findings most-severe-first and give each its citation ref. */
export function assignRefs(findings: Array<Omit<ReportFinding, "ref">>): ReportData["findings"] {
  return [...findings]
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        (b.riskScore ?? 0) - (a.riskScore ?? 0) ||
        (a.filePath ?? "").localeCompare(b.filePath ?? "") ||
        (a.startLine ?? 0) - (b.startLine ?? 0) ||
        a.id.localeCompare(b.id),
    )
    .map((f, i) => ({ ...f, ref: `F${i + 1}` }));
}

export function buildReportData(scan: ReportScan, findings: Array<Omit<ReportFinding, "ref">>): ReportData {
  const withRefs = assignRefs(findings);
  return {
    scan,
    findings: withRefs,
    byRef: new Map(withRefs.map((f) => [f.ref, f])),
    byId: new Map(withRefs.map((f) => [f.id, f])),
  };
}

function meta(f: ReportFinding): Record<string, unknown> {
  return f.metadata && typeof f.metadata === "object" && !Array.isArray(f.metadata)
    ? (f.metadata as Record<string, unknown>)
    : {};
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

function cut(s: string | null | undefined, n: number): string | undefined {
  if (!s) return undefined;
  return s.length > n ? `${s.slice(0, n)}… [truncated]` : s;
}

export function severityCounts(findings: ReportFinding[]): Record<string, number> {
  const c: Record<string, number> = Object.fromEntries(SEVERITIES.map((s) => [s.toLowerCase(), 0]));
  for (const f of findings) {
    const k = f.severity.toLowerCase();
    if (k in c) c[k]++;
  }
  return c;
}

/** Values for the template's explicit {{placeholders}}. */
export function placeholderValues(
  data: ReportData,
  delta: DeltaSummary | null,
  now: Date,
): Record<string, string | number | null> {
  const counted = data.findings.filter((f) => !SUPPRESSED.has(f.status));
  const sev = severityCounts(counted);
  const s = data.scan;
  return {
    "scan.id": s.id,
    "scan.repository": s.projectName,
    "scan.repository_url": s.repoUrl,
    "scan.branch": s.branch,
    "scan.commit": s.commitSha,
    "scan.type": s.scanType,
    "scan.status": s.status,
    "scan.date": (s.completedAt ?? s.createdAt).toISOString().replace("T", " ").slice(0, 16) + " UTC",
    "scan.gate_result": s.gateResult,
    "scan.files_scanned": s.filesScanned,
    "scan.dependencies_scanned": s.depsScanned,
    "findings.total": counted.length,
    "findings.open_count": data.findings.filter((f) => ACTIVE.has(f.status)).length,
    "findings.critical_count": sev.critical,
    "findings.high_count": sev.high,
    "findings.medium_count": sev.medium,
    "findings.low_count": sev.low,
    "findings.info_count": sev.info,
    "findings.new_count": delta ? delta.newFindingIds.filter((id) => data.byId.has(id)).length : null,
    "findings.fixed_count": delta && delta.fixedComparable ? delta.fixed.length : null,
    "findings.false_positive_count": data.findings.length - counted.length,
    "report.date": now.toISOString().replace("T", " ").slice(0, 16) + " UTC",
  };
}

// ─── Filters ──────────────────────────────────────────────────────────

function strList(v: unknown): string[] | undefined {
  if (typeof v === "string" && v.trim()) return [v.trim().toUpperCase()];
  if (Array.isArray(v)) {
    const out = v.filter((x): x is string => typeof x === "string" && !!x.trim()).map((x) => x.trim().toUpperCase());
    return out.length ? out : undefined;
  }
  return undefined;
}

function normalizeCwe(v: unknown): string | undefined {
  const m = typeof v === "string" || typeof v === "number" ? String(v).match(/(\d+)/) : null;
  return m ? `CWE-${m[1]}` : undefined;
}

export function filterFindings(data: ReportData, args: Record<string, unknown>): ReportFinding[] {
  const severity = strList(args.severity);
  const scanner = strList(args.scanner);
  const status = strList(args.status);
  const cwe = normalizeCwe(args.cwe);
  const category = typeof args.category === "string" ? args.category.trim().toLowerCase() : "";
  const fileContains = typeof args.fileContains === "string" ? args.fileContains.trim().toLowerCase() : "";
  const includeFp = args.includeFalsePositives === true || !!status?.includes("FALSE_POSITIVE");
  return data.findings.filter(
    (f) =>
      (includeFp || !SUPPRESSED.has(f.status)) &&
      (!severity || severity.includes(f.severity)) &&
      (!scanner || scanner.some((s) => f.scanner.includes(s))) &&
      (!status || status.includes(f.status)) &&
      (!cwe || normalizeCwe(f.cweId) === cwe) &&
      (!category || findingCategory(f).toLowerCase().includes(category)) &&
      (!fileContains || (f.filePath ?? "").toLowerCase().includes(fileContains)) &&
      (args.newOnly !== true || f.isNew === true),
  );
}

function listItem(f: ReportFinding) {
  const m = meta(f);
  return {
    ref: f.ref,
    severity: f.severity,
    scanner: f.scanner,
    title: f.title,
    category: findingCategory(f),
    cwe: f.cweId ?? undefined,
    cve: f.cveId ?? undefined,
    package: str(m.packageName) ? `${m.packageName}@${m.packageVersion ?? "?"}` : undefined,
    location: f.filePath ? `${f.filePath}${f.startLine ? `:${f.startLine}` : ""}` : undefined,
    status: f.status,
    isNew: f.isNew ?? undefined,
    riskScore: f.riskScore ?? undefined,
  };
}

// ─── Tools ────────────────────────────────────────────────────────────

function scanSummary(data: ReportData) {
  const counted = data.findings.filter((f) => !SUPPRESSED.has(f.status));
  const open = counted.filter((f) => ACTIVE.has(f.status));
  const statusCounts: Record<string, number> = {};
  const scanners: Record<string, number> = {};
  const categories = new Map<string, number>();
  for (const f of data.findings) statusCounts[f.status] = (statusCounts[f.status] ?? 0) + 1;
  for (const f of counted) {
    scanners[f.scanner] = (scanners[f.scanner] ?? 0) + 1;
    const c = findingCategory(f);
    categories.set(c, (categories.get(c) ?? 0) + 1);
  }
  const s = data.scan;
  return {
    scanId: s.id,
    repository: s.projectName,
    repositoryUrl: s.repoUrl,
    branch: s.branch,
    commit: s.commitSha,
    scanType: s.scanType,
    status: s.status,
    buildGate: s.gateResult,
    startedAt: s.createdAt.toISOString(),
    completedAt: s.completedAt?.toISOString() ?? null,
    filesScanned: s.filesScanned,
    dependenciesScanned: s.depsScanned,
    totalFindings: counted.length,
    falsePositivesExcluded: data.findings.length - counted.length,
    severityCounts: severityCounts(counted),
    openSeverityCounts: severityCounts(open),
    statusCounts,
    newSinceBaseline: counted.filter((f) => f.isNew === true).length,
    scanners,
    topCategories: [...categories.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([category, count]) => ({ category, count })),
  };
}

function listFindings(data: ReportData, args: Record<string, unknown>) {
  let rows = filterFindings(data, args);
  if (args.sort === "risk") rows = [...rows].sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0));
  const limit = Math.min(Math.max(Number(args.limit) || 20, 1), LIST_MAX);
  const offset = Math.max(Number(args.offset) || 0, 0);
  return {
    total: rows.length,
    offset,
    returned: Math.min(limit, Math.max(rows.length - offset, 0)),
    items: rows.slice(offset, offset + limit).map(listItem),
  };
}

function getFinding(data: ReportData, args: Record<string, unknown>) {
  const refs = (Array.isArray(args.refs) ? args.refs : [args.ref ?? args.refs])
    .filter((r): r is string => typeof r === "string")
    .slice(0, 5);
  return {
    findings: refs.map((raw) => {
      const ref = raw.trim().toUpperCase().replace(/^\[|\]$/g, "");
      const f = data.byRef.get(ref);
      if (!f) return { ref, error: "No finding with this ref exists in the scan." };
      const m = meta(f);
      const sections = (m.reportSections && typeof m.reportSections === "object" ? m.reportSections : {}) as Record<string, unknown>;
      return {
        ...listItem(f),
        description: cut(f.description, DESCRIPTION_CHARS),
        ruleId: f.ruleId ?? undefined,
        confidence: f.confidence ?? undefined,
        snippet: cut(f.snippet, SNIPPET_CHARS),
        fixVersion: str(m.fixVersion),
        license: str(m.licenseExpression),
        dependencyPath: str(m.dependencyPathText),
        impact: cut(str(sections.impact), 600),
        remediation: cut(
          Array.isArray(sections.remediation)
            ? sections.remediation.filter((r): r is string => typeof r === "string").join(" ")
            : str(sections.remediation),
          800,
        ),
      };
    }),
  };
}

function groupKey(f: ReportFinding, by: string): string {
  const m = meta(f);
  switch (by) {
    case "severity":
      return f.severity;
    case "scanner":
      return f.scanner;
    case "cwe":
      return f.cweId ?? "(none)";
    case "category":
      return findingCategory(f);
    case "file":
      return f.filePath ?? "(no file)";
    case "status":
      return f.status;
    case "rule":
      return f.ruleId ?? "(none)";
    case "package":
      return str(m.packageName) ? `${m.packageName}@${m.packageVersion ?? "?"}` : "(not a package finding)";
    default:
      return "(all)";
  }
}

function aggregate(data: ReportData, args: Record<string, unknown>) {
  const by = typeof args.groupBy === "string" ? args.groupBy : "severity";
  const rows = filterFindings(data, args);
  const groups = new Map<string, { count: number; criticalHigh: number; refs: string[] }>();
  for (const f of rows) {
    const k = groupKey(f, by);
    const g = groups.get(k) ?? { count: 0, criticalHigh: 0, refs: [] };
    g.count++;
    if (severityRank(f.severity) <= 1) g.criticalHigh++;
    if (g.refs.length < 3) g.refs.push(f.ref);
    groups.set(k, g);
  }
  const top = Math.min(Math.max(Number(args.top) || 10, 1), AGG_MAX);
  const sorted = [...groups.entries()].sort((a, b) =>
    by === "severity" ? severityRank(a[0]) - severityRank(b[0]) : b[1].criticalHigh - a[1].criticalHigh || b[1].count - a[1].count,
  );
  return {
    groupBy: by,
    totalMatching: rows.length,
    groups: sorted.slice(0, top).map(([key, g]) => ({ key, count: g.count, criticalHigh: g.criticalHigh, exampleRefs: g.refs })),
    otherGroups: Math.max(sorted.length - top, 0),
  };
}

async function compare(data: ReportData, sources: ReportSources) {
  const delta = await sources.delta();
  if (!delta) return { available: false, note: "No previous scan of this repository to compare with." };
  const newFindings = delta.newFindingIds
    .map((id) => data.byId.get(id))
    .filter((f): f is ReportFinding => !!f && !SUPPRESSED.has(f.status));
  const bySeverity: Record<string, { new: number; fixed: number }> = {};
  for (const s of SEVERITIES) bySeverity[s] = { new: 0, fixed: 0 };
  newFindings.forEach((f) => bySeverity[f.severity] && bySeverity[f.severity].new++);
  if (delta.fixedComparable) delta.fixed.forEach((f) => bySeverity[f.severity] && bySeverity[f.severity].fixed++);
  return {
    available: true,
    previousScan: { id: delta.baselineScanId, type: delta.baselineScanType, completedAt: delta.baselineCompletedAt },
    newCount: newFindings.length,
    fixedCount: delta.fixedComparable ? delta.fixed.length : null,
    fixedNote: delta.fixedComparable
      ? "Fixed findings no longer exist in this scan, so they have no ref; describe them by title."
      : "Fixed findings cannot be counted: one of the two scans did not cover the whole repository.",
    persistingCount: delta.persistingCount,
    bySeverity,
    newFindings: newFindings.slice(0, 25).map(listItem),
    fixed: delta.fixedComparable ? delta.fixed.slice(0, 25) : [],
  };
}

async function compliance(data: ReportData, sources: ReportSources, args: Record<string, unknown>) {
  const framework = typeof args.framework === "string" && args.framework.trim() ? args.framework.trim() : null;
  const res = await sources.compliance(framework);
  return {
    available: res.available,
    note: res.note,
    frameworks: res.reports.map((r) => ({
      framework: r.framework,
      mappingSource: r.source,
      totalControls: r.totalControls,
      impactedControls: r.impactedControls,
      gaps: r.gaps.slice(0, 15).map((g) => ({
        controlId: g.controlId,
        title: g.title,
        findingCount: g.findingCount,
        criticalHighCount: g.criticalHighCount,
        refs: g.findingIds
          .map((id) => data.byId.get(id))
          .filter((f): f is ReportFinding => !!f && !SUPPRESSED.has(f.status))
          .slice(0, 8)
          .map((f) => f.ref),
      })),
    })),
  };
}

async function dependencies(data: ReportData, sources: ReportSources) {
  const sbom = await sources.dependencies();
  const pkgFindings = data.findings.filter(
    (f) => !SUPPRESSED.has(f.status) && (f.scanner === "SCA" || f.scanner === "MALICIOUS_PKG" || f.scanner === "CONTAINER"),
  );
  const packages = new Map<string, { severity: string; count: number; refs: string[]; fixVersion?: string }>();
  for (const f of pkgFindings) {
    const m = meta(f);
    const key = str(m.packageName) ? `${m.packageName}@${m.packageVersion ?? "?"}` : f.title;
    const p = packages.get(key) ?? { severity: f.severity, count: 0, refs: [] };
    p.count++;
    if (severityRank(f.severity) < severityRank(p.severity)) p.severity = f.severity;
    if (p.refs.length < 4) p.refs.push(f.ref);
    p.fixVersion ??= str(m.fixVersion);
    packages.set(key, p);
  }
  return {
    dependenciesScanned: data.scan.depsScanned,
    sbom,
    dependencyFindings: pkgFindings.length,
    dependencyFindingsBySeverity: severityCounts(pkgFindings),
    licenseFindings: pkgFindings.filter((f) => str(meta(f).licenseExpression)).length,
    topPackages: [...packages.entries()]
      .sort((a, b) => severityRank(a[1].severity) - severityRank(b[1].severity) || b[1].count - a[1].count)
      .slice(0, 20)
      .map(([pkg, p]) => ({ package: pkg, worstSeverity: p.severity, findings: p.count, fixVersion: p.fixVersion, refs: p.refs })),
  };
}

/** Run one tool call. Unknown tools and bad arguments come back as { error }. */
export async function runTool(data: ReportData, sources: ReportSources, call: ToolCall): Promise<unknown> {
  const args = call.args && typeof call.args === "object" ? call.args : {};
  try {
    switch (call.tool) {
      case "get_scan_summary":
        return scanSummary(data);
      case "list_findings":
        return listFindings(data, args);
      case "get_finding":
        return getFinding(data, args);
      case "aggregate_findings":
        return aggregate(data, args);
      case "compare_with_previous_scan":
        return await compare(data, sources);
      case "get_compliance_mapping":
        return await compliance(data, sources, args);
      case "get_dependency_summary":
        return await dependencies(data, sources);
      default:
        return { error: `Unknown tool "${call.tool}".` };
    }
  } catch (e) {
    return { error: `Tool failed: ${e instanceof Error ? e.message : String(e)}` };
  }
}

/** Stable key for de-duplicating identical calls across sections. */
export function toolCallKey(call: ToolCall): string {
  const args = call.args ?? {};
  const sorted = Object.keys(args)
    .sort()
    .map((k) => [k, args[k]]);
  return `${call.tool}:${JSON.stringify(sorted)}`;
}
