const MAX_FINDINGS = 200;
const SNIPPET_MAX = 1200;
const META_MAX = 8000;

export type AssessmentFindingRow = {
  scanner: string;
  severity: string;
  title: string;
  description: string;
  filePath: string | null;
  startLine: number | null;
  endLine: number | null;
  snippet: string | null;
  ruleId: string | null;
  cweId: string | null;
  cveId: string | null;
  confidence: number | null;
  masked: boolean;
  metadata: unknown;
};

function truncate(s: string | null | undefined, n: number): string | undefined {
  if (!s) return undefined;
  const t = s.trim();
  if (t.length <= n) return t;
  return `${t.slice(0, n)}…`;
}

/** Structured payload for the assessment-report LLM — evidence only, no UI card copy. */
export function buildAssessmentReportUserPayload(args: {
  projectName: string;
  scanId: string;
  scanStatus: string;
  completedAt: string | null;
  filesScanned: number;
  architectureOverview?: string | null;
  findings: AssessmentFindingRow[];
}): string {
  const sorted = [...args.findings].sort((a, b) => {
    const sev = (x: AssessmentFindingRow) =>
      ({ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }[x.severity] ?? 5);
    return sev(a) - sev(b) || (a.filePath || "").localeCompare(b.filePath || "");
  });

  const trimmed = sorted.slice(0, MAX_FINDINGS).map((f, index) => {
    const meta = f.metadata;
    const metaStr =
      meta && typeof meta === "object"
        ? truncate(JSON.stringify(meta), META_MAX)
        : undefined;

    return {
      id: index + 1,
      scanner: f.scanner,
      severity: f.severity,
      title: f.title,
      description: truncate(f.description, 4000),
      filePath: f.filePath,
      startLine: f.startLine,
      endLine: f.endLine,
      snippet: truncate(f.snippet, SNIPPET_MAX),
      ruleId: f.ruleId,
      cweId: f.cweId,
      cveId: f.cveId,
      confidence: f.confidence,
      masked: f.masked,
      metadataJson: metaStr,
    };
  });

  const reviewedPaths = [
    ...new Set(
      args.findings
        .map((f) => f.filePath)
        .filter((p): p is string => Boolean(p)),
    ),
  ].sort();

  return JSON.stringify(
    {
      instruction:
        "Generate the full professional Markdown assessment report per your system instructions. Use ONLY evidence from this JSON.",
      projectName: args.projectName,
      scanId: args.scanId,
      scanStatus: args.scanStatus,
      completedAt: args.completedAt,
      filesScannedCount: args.filesScanned,
      architectureOverview: args.architectureOverview || undefined,
      reviewedFilePaths: reviewedPaths.slice(0, 400),
      findings: trimmed,
      findingCount: args.findings.length,
      truncated: args.findings.length > MAX_FINDINGS,
    },
    null,
    2,
  );
}
