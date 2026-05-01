import * as fs from "fs";
import * as path from "path";
import {
  normalizeAttackPreconditionsValues,
  normalizeCustomerFacingText,
} from "@/lib/report-text";

export type ReportSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface ReportFindingInput {
  id?: string;
  scanner: string;
  severity: string;
  title: string;
  description: string;
  filePath?: string | null;
  startLine?: number | null;
  endLine?: number | null;
  snippet?: string | null;
  ruleId?: string | null;
  cweId?: string | null;
  cveId?: string | null;
  confidence?: number | null;
  metadata?: unknown;
  masked?: boolean | null;
}

export interface LineExplanation {
  lineNumber?: number;
  code: string;
  explanation: string;
}

export interface AttackPreconditions {
  authenticationRequired: string;
  privilegesRequired: string;
  userInteractionRequired: string;
  sensitiveDataExposure: string;
  privilegeEscalationPotential: string;
  chainability: string;
}

export interface VulnerabilityReportDetails {
  vulnerabilityName: string;
  severity: ReportSeverity;
  confidenceLevel: string;
  confidenceScore?: number;
  affectedFilePath: string;
  affectedFunction: string;
  exactLineNumber: number | null;
  lineRange: string;
  language: string;
  vulnerableSourceCode: string;
  lineByLineExplanation: LineExplanation[];
  rootCause: string;
  realWorldAttackScenario: string;
  advancedAttackerReasoning: string;
  attackPreconditions: AttackPreconditions;
  stepsToReproduce: string[];
  proofOfConcept: string;
  expectedVulnerableBehavior: string;
  businessImpact: string;
  secureFixExplanation: string;
  secureCodeExample: string;
  securityTests: string;
  regressionPrevention: string;
}

export interface ReportVulnerability {
  id?: string;
  scanner: string;
  ruleId?: string | null;
  cweId?: string | null;
  cveId?: string | null;
  status?: string;
  /** Original scanner/LLM finding text (developer-facing). */
  scannerDescription?: string;
  report: VulnerabilityReportDetails;
}

export interface SecurityScanReport {
  title: "Security Scan Report";
  scanId?: string;
  projectName?: string;
  generatedAt: string;
  executiveSummary: {
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    overallRiskRating: "Critical" | "High" | "Medium" | "Low" | "Informational";
  };
  vulnerabilities: ReportVulnerability[];
  /** Authorized-use scope statement */
  scope?: string;
  methodology?: string[];
  architectureOverview?: string;
  appendix?: {
    testedFilesSample?: string[];
    rulesVersion?: string;
    assumptions?: string[];
  };
}

interface SourceContext {
  sourceSnippet?: string;
  affectedFunction?: string;
  language?: string;
}

interface ReportHints {
  affectedFunction?: string;
  /** Untrusted input entry point (LLM SAST). */
  inputSource?: string;
  /** Dangerous operation (LLM SAST). */
  dangerousSink?: string;
  missingSecurityControl?: string;
  /** Source→sink path narrative (LLM SAST). */
  reachabilityExplanation?: string;
  owaspCategory?: string;
  validationStatus?: string;
  lineByLineExplanation?: LineExplanation[] | string[];
  rootCause?: string;
  realWorldAttackScenario?: string;
  advancedAttackerReasoning?: string;
  stepsToReproduce?: string[];
  proofOfConcept?: string;
  expectedVulnerableBehavior?: string;
  businessImpact?: string;
  secureFixExplanation?: string;
  secureCodeExample?: string;
  securityTests?: string;
  regressionPrevention?: string;
  attackPreconditions?: Partial<AttackPreconditions>;
}

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export async function enrichRawFindingsWithSource<T extends ReportFindingInput>(
  findings: T[],
  workDir: string,
): Promise<T[]> {
  return findings.map((finding) => {
    const source = getSourceContext(workDir, finding);
    const report = buildVulnerabilityReportDetails(finding, source);
    const metadata = asObject(finding.metadata);

    return {
      ...finding,
      snippet:
        finding.snippet ||
        (finding.masked ? finding.snippet : source.sourceSnippet) ||
        undefined,
      metadata: stripUndefined({
        ...metadata,
        report,
      }),
    };
  });
}

export function buildSecurityScanReport(args: {
  scanId?: string;
  projectName?: string;
  findings: ReportFindingInput[];
  generatedAt?: string;
  scope?: string;
  methodology?: string[];
  architectureOverview?: string;
  appendix?: SecurityScanReport["appendix"];
}): SecurityScanReport {
  const vulnerabilities = args.findings
    .map((finding) => {
      const fallbackReport = buildVulnerabilityReportDetails(finding);
      const stored = getStoredReport(finding);
      const report = stored
        ? mergeReportDetails(stored, fallbackReport)
        : fallbackReport;
      const desc = finding.description?.trim();
      return {
        id: finding.id,
        scanner: finding.scanner,
        ruleId: finding.ruleId,
        cweId: finding.cweId,
        cveId: finding.cveId,
        status: getStringField(finding, "status"),
        scannerDescription: desc || undefined,
        report,
      };
    })
    .sort(
      (a, b) =>
        (SEVERITY_RANK[b.report.severity] || 0) -
          (SEVERITY_RANK[a.report.severity] || 0) ||
        a.report.affectedFilePath.localeCompare(b.report.affectedFilePath),
    );

  const criticalCount = vulnerabilities.filter(
    (v) => v.report.severity === "CRITICAL",
  ).length;
  const highCount = vulnerabilities.filter(
    (v) => v.report.severity === "HIGH",
  ).length;
  const mediumCount = vulnerabilities.filter(
    (v) => v.report.severity === "MEDIUM",
  ).length;
  const lowCount = vulnerabilities.filter(
    (v) => v.report.severity === "LOW",
  ).length;
  const infoCount = vulnerabilities.filter(
    (v) => v.report.severity === "INFO",
  ).length;

  return {
    title: "Security Scan Report",
    scanId: args.scanId,
    projectName: args.projectName,
    generatedAt: args.generatedAt || new Date().toISOString(),
    executiveSummary: {
      totalVulnerabilities: vulnerabilities.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      overallRiskRating: getOverallRiskRating({
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
      }),
    },
    vulnerabilities,
    scope:
      args.scope ||
      "Authorized targets only (owned codebases, labs, CTF challenges, or environments where you have explicit permission).",
    methodology: args.methodology || [
      "Static application security testing (pattern rules + optional LLM-assisted analysis)",
      "Software composition analysis (dependency advisories)",
      "Secret and sensitive-path detection with redaction",
      "Heuristic architecture and route mapping from repository structure",
      "Machine-generated findings: validate in your environment; static analysis does not prove exploitability.",
    ],
    architectureOverview: args.architectureOverview,
    appendix: args.appendix,
  };
}

export function buildVulnerabilityReportDetails(
  finding: ReportFindingInput,
  source: SourceContext = {},
): VulnerabilityReportDetails {
  const metadata = asObject(finding.metadata);
  const hints = getReportHints(metadata);
  const category = classifyFinding(finding);
  const template = getCategoryTemplate(category, finding);
  const severity = normalizeSeverity(finding.severity);
  const language = source.language || languageFromFilePath(finding.filePath);
  const vulnerableSourceCode =
    finding.snippet ||
    (finding.masked ? finding.snippet : source.sourceSnippet) ||
    "Source code snippet was not available for this finding.";

  const lineByLineExplanation =
    normalizeLineExplanations(hints.lineByLineExplanation) ||
    buildLineExplanations(vulnerableSourceCode, finding, template.lineReason);

  const mergedPreconditions = {
    ...template.attackPreconditions,
    ...hints.attackPreconditions,
  };

  const attackPreconditions = normalizeAttackPreconditionsValues(
    mergedPreconditions as unknown as Record<string, unknown>,
  ) as unknown as AttackPreconditions;

  const norm = normalizeCustomerFacingText;

  return {
    vulnerabilityName: norm(finding.title) || finding.title,
    severity,
    confidenceLevel: formatConfidence(finding.confidence),
    confidenceScore: normalizeConfidenceScore(finding.confidence),
    affectedFilePath:
      finding.filePath ||
      getString(metadata.packageName) ||
      "No file path available",
    affectedFunction:
      hints.affectedFunction ||
      source.affectedFunction ||
      inferFunctionFromSnippet(vulnerableSourceCode) ||
      "Not identified",
    exactLineNumber: finding.startLine ?? null,
    lineRange: formatLineRange(finding.startLine, finding.endLine),
    language,
    vulnerableSourceCode,
    lineByLineExplanation: lineByLineExplanation.map((line) => ({
      ...line,
      explanation: norm(line.explanation),
      code: line.code,
    })),
    rootCause: norm(hints.rootCause || template.rootCause),
    realWorldAttackScenario: norm(
      hints.realWorldAttackScenario || template.realWorldAttackScenario,
    ),
    advancedAttackerReasoning: norm(
      hints.advancedAttackerReasoning || template.advancedAttackerReasoning,
    ),
    attackPreconditions,
    stepsToReproduce: (hints.stepsToReproduce || template.stepsToReproduce).map(
      (s) => norm(s),
    ),
    proofOfConcept: norm(
      selectProofOfConcept(
        hints.proofOfConcept,
        template.proofOfConcept,
        category,
      ),
    ),
    expectedVulnerableBehavior: norm(
      hints.expectedVulnerableBehavior ||
        template.expectedVulnerableBehavior,
    ),
    businessImpact: norm(hints.businessImpact || template.businessImpact),
    secureFixExplanation: norm(
      hints.secureFixExplanation || template.secureFixExplanation,
    ),
    secureCodeExample: hints.secureCodeExample || template.secureCodeExample,
    securityTests: norm(hints.securityTests || template.securityTests),
    regressionPrevention: norm(
      hints.regressionPrevention || template.regressionPrevention,
    ),
  };
}

export function renderSecurityScanReportMarkdown(
  report: SecurityScanReport,
): string {
  const lines: string[] = [];
  lines.push("# Security Scan Report");
  lines.push("");
  if (report.projectName) lines.push(`Project: ${report.projectName}`);
  if (report.scanId) lines.push(`Scan ID: ${report.scanId}`);
  lines.push(`Generated: ${report.generatedAt}`);
  lines.push("");
  if (report.scope) {
    lines.push("## Scope");
    lines.push(report.scope);
    lines.push("");
  }
  lines.push("## Executive Summary");
  lines.push(
    `- Total vulnerabilities: ${report.executiveSummary.totalVulnerabilities}`,
  );
  lines.push(`- Critical count: ${report.executiveSummary.criticalCount}`);
  lines.push(`- High count: ${report.executiveSummary.highCount}`);
  lines.push(`- Medium count: ${report.executiveSummary.mediumCount}`);
  lines.push(`- Low count: ${report.executiveSummary.lowCount}`);
  lines.push(`- Info count: ${report.executiveSummary.infoCount}`);
  lines.push(
    `- Overall risk rating: ${report.executiveSummary.overallRiskRating}`,
  );
  lines.push("");
  lines.push("### Risk summary");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  lines.push(`| Critical | ${report.executiveSummary.criticalCount} |`);
  lines.push(`| High | ${report.executiveSummary.highCount} |`);
  lines.push(`| Medium | ${report.executiveSummary.mediumCount} |`);
  lines.push(`| Low | ${report.executiveSummary.lowCount} |`);
  lines.push(`| Info | ${report.executiveSummary.infoCount} |`);
  lines.push("");
  if (report.methodology?.length) {
    lines.push("## Methodology");
    for (const m of report.methodology) lines.push(`- ${m}`);
    lines.push("");
  }
  if (report.architectureOverview) {
    lines.push("## Architecture overview");
    lines.push(report.architectureOverview);
    lines.push("");
  }
  lines.push("## Vulnerability Details");
  lines.push("");

  if (report.vulnerabilities.length === 0) {
    lines.push("No vulnerabilities were detected in this scan.");
    return lines.join("\n");
  }

  for (const vulnerability of report.vulnerabilities) {
    const item = vulnerability.report;
    lines.push(`### [${item.severity}] ${item.vulnerabilityName}`);
    lines.push("");
    if (vulnerability.scannerDescription?.trim()) {
      lines.push("#### Original scanner text");
      lines.push(vulnerability.scannerDescription.trim());
      lines.push("");
    }
    if (vulnerability.cweId) {
      lines.push("#### Classification");
      lines.push(`- CWE: ${vulnerability.cweId}`);
      lines.push("");
    }
    lines.push("#### Location");
    lines.push(`File: ${item.affectedFilePath}`);
    lines.push(`Function: ${item.affectedFunction}`);
    lines.push(`Lines: ${item.lineRange}`);
    lines.push("");
    lines.push("#### Vulnerable Code");
    lines.push(`\`\`\`${item.language}`);
    lines.push(escapeMarkdownFence(item.vulnerableSourceCode));
    lines.push("```");
    lines.push("");
    lines.push("#### Description");
    lines.push(item.rootCause);
    lines.push("");
    if (item.lineByLineExplanation.length > 0) {
      lines.push("#### Line-by-line notes");
      for (const explanation of item.lineByLineExplanation) {
        const lineLabel =
          explanation.lineNumber != null
            ? `Line ${explanation.lineNumber}`
            : "Line";
        lines.push(`- ${lineLabel}: ${explanation.explanation}`);
      }
      lines.push("");
    }
    lines.push("#### Attack reasoning");
    if ((item.realWorldAttackScenario || "").trim()) {
      lines.push(`**Real-world scenario:** ${item.realWorldAttackScenario}`);
      lines.push("");
    }
    lines.push(item.advancedAttackerReasoning);
    lines.push("");
    lines.push("Preconditions:");
    lines.push(
      `- Authentication needed: ${item.attackPreconditions.authenticationRequired}`,
    );
    lines.push(
      `- Privileges needed: ${item.attackPreconditions.privilegesRequired}`,
    );
    lines.push(
      `- User interaction: ${item.attackPreconditions.userInteractionRequired}`,
    );
    lines.push(
      `- Sensitive data exposure: ${item.attackPreconditions.sensitiveDataExposure}`,
    );
    lines.push(
      `- Privilege escalation: ${item.attackPreconditions.privilegeEscalationPotential}`,
    );
    lines.push(`- Chainability: ${item.attackPreconditions.chainability}`);
    lines.push("");
    lines.push("#### Steps to Reproduce");
    item.stepsToReproduce.forEach((step, index) => {
      lines.push(`${index + 1}. ${step}`);
    });
    lines.push("");
    if (item.proofOfConcept.trim()) {
      lines.push("#### Proof of Concept");
      lines.push("```bash");
      lines.push(escapeMarkdownFence(item.proofOfConcept));
      lines.push("```");
      lines.push("");
    }
    lines.push("#### Expected Vulnerable Behavior");
    lines.push(item.expectedVulnerableBehavior);
    lines.push("");
    lines.push("#### Impact");
    lines.push(item.businessImpact);
    lines.push("");
    lines.push("#### How to Fix");
    lines.push(item.secureFixExplanation);
    lines.push("");
    if (item.secureCodeExample.trim()) {
      lines.push("#### Secure Code Example");
      lines.push(`\`\`\`${item.language}`);
      lines.push(escapeMarkdownFence(item.secureCodeExample));
      lines.push("```");
      lines.push("");
    }
    lines.push("#### Security Tests");
    lines.push(...markdownSecurityTestsBlock(item.securityTests));
    lines.push("");
    lines.push("#### Regression Prevention");
    lines.push(item.regressionPrevention);
    lines.push("");
  }

  if (report.appendix) {
    lines.push("## Appendix");
    lines.push("");
    if (report.appendix.rulesVersion) {
      lines.push(`Rules / engine: ${report.appendix.rulesVersion}`);
      lines.push("");
    }
    if (report.appendix.assumptions?.length) {
      lines.push("### Assumptions");
      for (const a of report.appendix.assumptions) lines.push(`- ${a}`);
      lines.push("");
    }
    if (report.appendix.testedFilesSample?.length) {
      lines.push("### Sample of tested files");
      for (const f of report.appendix.testedFilesSample.slice(0, 40)) {
        lines.push(`- ${f}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

function selectProofOfConcept(
  hint: string | undefined,
  fallback: string | undefined,
  category: string,
): string {
  if (["dependency", "supply-chain", "iac"].includes(category)) return "";
  const value = hint || fallback || "";
  if (/localhost:3000\/example|Replace with a safe local request/i.test(value)) {
    return "";
  }
  return value;
}

function getSourceContext(
  workDir: string,
  finding: ReportFindingInput,
): SourceContext {
  if (!finding.filePath) return {};

  const root = path.resolve(workDir);
  const fullPath = path.resolve(workDir, finding.filePath);
  if (!fullPath.startsWith(root + path.sep) && fullPath !== root) return {};

  try {
    const content = fs.readFileSync(fullPath, "utf-8");
    const language = languageFromFilePath(finding.filePath);
    const affectedFunction = finding.startLine
      ? findEnclosingFunction(content, finding.startLine)
      : undefined;
    const sourceSnippet =
      finding.masked && finding.snippet
        ? finding.snippet
        : buildSourceSnippet(content, finding.startLine, finding.endLine);

    return { sourceSnippet, affectedFunction, language };
  } catch {
    return {};
  }
}

function buildSourceSnippet(
  content: string,
  startLine?: number | null,
  endLine?: number | null,
): string | undefined {
  if (!startLine) return undefined;
  const lines = content.split("\n");
  const start = Math.max(1, startLine - 2);
  const end = Math.min(lines.length, (endLine || startLine) + 2);
  return lines
    .slice(start - 1, end)
    .map((line, index) => `${start + index}: ${line}`)
    .join("\n");
}

function findEnclosingFunction(
  content: string,
  lineNumber: number,
): string | undefined {
  const lines = content.split("\n");
  const startIndex = Math.min(lines.length - 1, Math.max(0, lineNumber - 1));
  const patterns: RegExp[] = [
    /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/,
    /\b(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/,
    /\bdef\s+([A-Za-z_][\w]*)\s*\(/,
    /\bfunc\s+(?:\([^)]+\)\s*)?([A-Za-z_][\w]*)\s*\(/,
    /\b(?:public|private|protected|static|\s)+[<>\w\[\]]+\s+([A-Za-z_][\w]*)\s*\(/,
    /\bclass\s+([A-Za-z_$][\w$]*)/,
  ];

  for (let index = startIndex; index >= 0; index--) {
    const line = lines[index].trim();
    for (const pattern of patterns) {
      const match = line.match(pattern);
      if (match?.[1]) return match[1];
    }
  }

  return undefined;
}

function inferFunctionFromSnippet(snippet: string): string | undefined {
  return findEnclosingFunction(snippet, snippet.split("\n").length);
}

function getStoredReport(
  finding: ReportFindingInput,
): VulnerabilityReportDetails | null {
  const metadata = asObject(finding.metadata);
  const report = asObject(metadata.report);
  if (!report.vulnerabilityName || !report.severity) return null;
  return report as unknown as VulnerabilityReportDetails;
}

/** Fill empty fields in LLM/persisted `report` from template-backed `fallback` for export accuracy. */
function mergeReportDetails(
  partial: VulnerabilityReportDetails,
  fallback: VulnerabilityReportDetails,
): VulnerabilityReportDetails {
  const pick = (a: string, b: string) => {
    const t = a != null ? String(a).trim() : "";
    return t !== "" ? String(a).trim() : b;
  };
  const snippetUnavailable = "Source code snippet was not available for this finding.";
  const vulnCode = (() => {
    const p = partial.vulnerableSourceCode?.trim() ?? "";
    if (p && p !== snippetUnavailable) return partial.vulnerableSourceCode;
    return fallback.vulnerableSourceCode;
  })();

  const merged = overlayAttackPreconditions(
    partial.attackPreconditions,
    fallback.attackPreconditions,
  );

  const lines =
    Array.isArray(partial.lineByLineExplanation) &&
    partial.lineByLineExplanation.some((x) => (x.explanation || "").trim())
      ? partial.lineByLineExplanation
      : fallback.lineByLineExplanation;

  const steps =
    Array.isArray(partial.stepsToReproduce) &&
    partial.stepsToReproduce.some((s) => s.trim())
      ? partial.stepsToReproduce
      : fallback.stepsToReproduce;

  const sev = partial.severity;
  const severity: ReportSeverity = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
  ].includes(sev)
    ? (sev as ReportSeverity)
    : fallback.severity;

  return {
    vulnerabilityName: pick(partial.vulnerabilityName, fallback.vulnerabilityName),
    severity,
    confidenceLevel: pick(
      partial.confidenceLevel,
      fallback.confidenceLevel,
    ),
    confidenceScore: partial.confidenceScore ?? fallback.confidenceScore,
    affectedFilePath: pick(partial.affectedFilePath, fallback.affectedFilePath),
    affectedFunction: pick(partial.affectedFunction, fallback.affectedFunction),
    exactLineNumber: partial.exactLineNumber ?? fallback.exactLineNumber,
    lineRange: pick(partial.lineRange, fallback.lineRange),
    language: pick(partial.language, fallback.language),
    vulnerableSourceCode: vulnCode,
    lineByLineExplanation: lines,
    rootCause: pick(partial.rootCause, fallback.rootCause),
    realWorldAttackScenario: pick(
      partial.realWorldAttackScenario,
      fallback.realWorldAttackScenario,
    ),
    advancedAttackerReasoning: pick(
      partial.advancedAttackerReasoning,
      fallback.advancedAttackerReasoning,
    ),
    attackPreconditions: merged,
    stepsToReproduce: steps,
    proofOfConcept: pick(partial.proofOfConcept, fallback.proofOfConcept),
    expectedVulnerableBehavior: pick(
      partial.expectedVulnerableBehavior,
      fallback.expectedVulnerableBehavior,
    ),
    businessImpact: pick(partial.businessImpact, fallback.businessImpact),
    secureFixExplanation: pick(
      partial.secureFixExplanation,
      fallback.secureFixExplanation,
    ),
    secureCodeExample: pick(partial.secureCodeExample, fallback.secureCodeExample),
    securityTests: pick(partial.securityTests, fallback.securityTests),
    regressionPrevention: pick(
      partial.regressionPrevention,
      fallback.regressionPrevention,
    ),
  };
}

function overlayAttackPreconditions(
  partial: AttackPreconditions | undefined,
  fallback: AttackPreconditions,
): AttackPreconditions {
  if (!partial) return fallback;
  const out: AttackPreconditions = { ...fallback };
  (Object.keys(out) as (keyof AttackPreconditions)[]).forEach((key) => {
    const v = partial[key];
    if (v != null && String(v).trim() !== "") out[key] = v;
  });
  return out;
}

function getReportHints(metadata: Record<string, unknown>): ReportHints {
  return asObject(metadata.reportHints) as ReportHints;
}

function normalizeLineExplanations(
  value: ReportHints["lineByLineExplanation"],
): LineExplanation[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  return value.map((entry) => {
    if (typeof entry === "string") {
      return { code: "", explanation: entry };
    }
    return {
      lineNumber: entry.lineNumber,
      code: entry.code || "",
      explanation: entry.explanation,
    };
  });
}

function buildLineExplanations(
  snippet: string,
  finding: ReportFindingInput,
  reason: string,
): LineExplanation[] {
  const parsedLines = parseSnippetLines(snippet);
  if (parsedLines.length === 0) {
    return [
      {
        lineNumber: finding.startLine ?? undefined,
        code: snippet,
        explanation: reason,
      },
    ];
  }

  return parsedLines.map((line) => {
    const isPrimary =
      finding.startLine == null ||
      line.lineNumber == null ||
      line.lineNumber === finding.startLine ||
      (finding.endLine != null &&
        line.lineNumber >= finding.startLine &&
        line.lineNumber <= finding.endLine);

    return {
      lineNumber: line.lineNumber,
      code: line.code,
      explanation: isPrimary
        ? reason
        : "Context line included to show how data and control flow reach the vulnerable statement.",
    };
  });
}

function parseSnippetLines(
  snippet: string,
): Array<{ lineNumber?: number; code: string }> {
  return snippet
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => {
      const match = line.match(/^\s*(\d+):\s?(.*)$/);
      if (!match) return { code: line };
      return { lineNumber: parseInt(match[1], 10), code: match[2] };
    });
}

function classifyFinding(finding: ReportFindingInput): string {
  const haystack = `${finding.scanner} ${finding.title} ${finding.description} ${finding.ruleId || ""} ${finding.cweId || ""}`.toLowerCase();
  if (/cwe-89|sql/.test(haystack)) return "sql-injection";
  if (/cwe-79|xss|cross.site|innerhtml/.test(haystack)) return "xss";
  if (/cwe-78|command|exec|rce|shell/.test(haystack)) return "command-injection";
  if (/cwe-22|path traversal|directory traversal/.test(haystack)) return "path-traversal";
  if (/cwe-918|ssrf|server.side.request/.test(haystack)) return "ssrf";
  if (/cwe-798|secret|credential|password|token|api key/.test(haystack))
    return "secret";
  if (/cwe-338|cwe-328|crypto|random|md5|sha1/.test(haystack))
    return "weak-crypto";
  if (/cwe-863|cwe-639|auth|access control|idor|privilege/.test(haystack))
    return "access-control";
  if (/cwe-601|open redirect|redirect/.test(haystack)) return "redirect";
  if (/cwe-352|csrf/.test(haystack)) return "csrf";
  if (/cwe-611|xxe|xml/.test(haystack)) return "xxe";
  if (/cwe-502|deserialize|deserialization/.test(haystack))
    return "deserialization";
  if (/cwe-942|cors/.test(haystack)) return "cors";
  if (/sca|cve-|osv|vulnerable dependency/.test(haystack)) return "dependency";
  if (/cwe-506|malicious|typosquat|supply chain/.test(haystack))
    return "supply-chain";
  if (/iac|docker|terraform|kubernetes|container|privileged/.test(haystack))
    return "iac";
  return "generic";
}

function getCategoryTemplate(
  category: string,
  finding: ReportFindingInput,
): Omit<
  VulnerabilityReportDetails,
  | "vulnerabilityName"
  | "severity"
  | "confidenceLevel"
  | "confidenceScore"
  | "affectedFilePath"
  | "affectedFunction"
  | "exactLineNumber"
  | "lineRange"
  | "language"
  | "vulnerableSourceCode"
  | "lineByLineExplanation"
> & { lineReason: string } {
  const location = formatLocation(finding);
  const metadata = asObject(finding.metadata);
  const packageName = getString(metadata.packageName) || "the affected package";
  const packageVersion = getString(metadata.packageVersion) || getString(metadata.version);
  const fixVersion = getString(metadata.fixVersion);
  const common = {
    attackPreconditions: {
      authenticationRequired: "Depends on whether the affected code path is behind authentication.",
      privilegesRequired: "No elevated privileges are assumed unless the endpoint or job requires them.",
      userInteractionRequired: "Usually none beyond submitting input to the affected code path.",
      sensitiveDataExposure: "Possible if the vulnerable code handles credentials, records, files, or internal service responses.",
      privilegeEscalationPotential: "Possible when the vulnerable code runs with broader server-side permissions than the attacker has.",
      chainability: "Can be chained with weak authorization, exposed secrets, or excessive service permissions.",
    },
  };

  const templates: Record<string, ReturnType<typeof template>> = {
    "sql-injection": template({
      lineReason:
        "The statement builds or executes SQL using data that may be attacker-controlled, which can change query structure instead of treating input as data.",
      rootCause:
        "User-controlled input reaches a SQL query without parameter binding or a safe query builder boundary.",
      realWorldAttackScenario:
        "An attacker submits crafted input through the affected endpoint or form so the database interprets part of the input as SQL syntax.",
      advancedAttackerReasoning:
        "The attacker first identifies the input that influences the query, then probes for boolean, union, time-based, or error-based behavior. If the query runs under a privileged database account, this can expose unrelated rows or support follow-on account takeover.",
      stepsToReproduce: [
        `Locate the request or job path that reaches ${location}.`,
        "Submit a benign value and record the normal response.",
        "Submit a safe SQL metacharacter test value such as ' OR '1'='1 and compare the response.",
      ],
      proofOfConcept:
        "curl -X POST http://localhost:3000/example -H 'Content-Type: application/json' -d '{\"search\":\"test' OR '1'='1\"}'",
      expectedVulnerableBehavior:
        "The response changes, returns unexpected records, raises a SQL syntax error, or takes noticeably longer for time-based probes.",
      businessImpact:
        "Attackers may read, modify, or delete company data and can bypass application-level authorization enforced after the query.",
      secureFixExplanation:
        "Use parameterized queries or an ORM API that binds values separately from SQL syntax. Validate input for business rules before it reaches the data layer.",
      secureCodeExample:
        "const rows = await db.query(\"SELECT * FROM users WHERE email = $1\", [email]);",
      securityTests:
        "await request(app).post('/example').send({ search: \"test' OR '1'='1\" }).expect(200);\nexpect(db.query).toHaveBeenCalledWith(expect.stringContaining('$1'), expect.any(Array));",
      regressionPrevention:
        "Ban raw string-concatenated SQL in code review, add SAST rules for query construction, and require tests for malicious query metacharacters.",
      attackPreconditions: common.attackPreconditions,
    }),
    xss: template({
      lineReason:
        "The line renders or assigns HTML from a value that may contain attacker-controlled markup or script.",
      rootCause:
        "Untrusted data is inserted into an HTML or JavaScript execution context without sanitization or contextual output encoding.",
      realWorldAttackScenario:
        "An attacker stores or reflects markup that runs in another user's browser when the affected page or component renders.",
      advancedAttackerReasoning:
        "The attacker looks for a controllable value that reaches the DOM, then uses script execution to steal session data, perform actions as the victim, or pivot to internal admin workflows.",
      stepsToReproduce: [
        `Find the UI or API value rendered by ${location}.`,
        "Submit a harmless XSS probe payload.",
        "Open the affected page and observe whether the payload executes or is rendered as markup.",
      ],
      proofOfConcept:
        "curl -X POST http://localhost:3000/example -H 'Content-Type: application/json' -d '{\"name\":\"<img src=x onerror=alert(1)>\"}'",
      expectedVulnerableBehavior:
        "The browser interprets the payload as HTML or JavaScript instead of displaying it as text.",
      businessImpact:
        "A successful attack can hijack user sessions, perform privileged actions, deface pages, or exfiltrate sensitive browser-visible data.",
      secureFixExplanation:
        "Render untrusted values as text, sanitize allowed HTML with a proven sanitizer, and enforce a restrictive Content Security Policy.",
      secureCodeExample:
        "return <div>{userSuppliedText}</div>;\n// If HTML is required, sanitize first with a vetted allowlist sanitizer.",
      securityTests:
        "render(<Component value={'<img src=x onerror=alert(1)>'} />);\nexpect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();",
      regressionPrevention:
        "Disallow direct innerHTML/dangerouslySetInnerHTML without a sanitizer wrapper and add component tests for encoded malicious markup.",
      attackPreconditions: common.attackPreconditions,
    }),
    "command-injection": template({
      lineReason:
        "The line constructs a shell command or process invocation in a way that can mix user input with executable shell syntax.",
      rootCause:
        "Untrusted input reaches shell execution without an allowlist and without separating executable arguments from shell parsing.",
      realWorldAttackScenario:
        "An attacker supplies shell metacharacters through an API, CLI argument, webhook field, or uploaded metadata to execute unintended commands.",
      advancedAttackerReasoning:
        "The attacker confirms command execution with a low-impact command, then chains it to read environment variables, source code, cloud metadata, or credentials available to the worker process.",
      stepsToReproduce: [
        `Reach the code path that invokes the command at ${location}.`,
        "Submit a safe command-separator probe.",
        "Confirm whether harmless command output or timing changes appear.",
      ],
      proofOfConcept:
        "curl -X POST http://localhost:3000/example -H 'Content-Type: application/json' -d '{\"name\":\"file.txt; whoami\"}'",
      expectedVulnerableBehavior:
        "The process executes an unintended extra command or behaves differently when shell metacharacters are present.",
      businessImpact:
        "Remote command execution can expose source code, secrets, internal network access, and data reachable by the application runtime.",
      secureFixExplanation:
        "Avoid shell execution. Use execFile/spawn with a fixed executable and an argument array, and validate each argument against an allowlist.",
      secureCodeExample:
        "execFile('git', ['clone', '--depth', '1', repoUrl, destination], { timeout: 120000 });",
      securityTests:
        "await expect(runCommand('repo; whoami')).rejects.toThrow(/invalid/i);\nexpect(execFile).toHaveBeenCalledWith('git', expect.any(Array), expect.any(Object));",
      regressionPrevention:
        "Centralize command execution behind a safe wrapper and block child_process.exec for request-influenced data in code review.",
      attackPreconditions: {
        ...common.attackPreconditions,
        privilegeEscalationPotential:
          "High if the process runs with deployment, filesystem, cloud, or database privileges.",
      },
    }),
    secret: template({
      lineReason:
        "The line contains a credential-like value or high-entropy token that appears to be stored in source.",
      rootCause:
        "Sensitive credentials are committed or embedded directly instead of being loaded from a secret manager or protected runtime environment.",
      realWorldAttackScenario:
        "Anyone with repository, artifact, log, or package access can copy the credential and authenticate to the downstream service.",
      advancedAttackerReasoning:
        "The attacker validates the credential against likely providers, then uses granted scopes to enumerate data, create persistence, or pivot to more privileged systems.",
      stepsToReproduce: [
        `Inspect the finding at ${location}.`,
        "Verify whether the value is a real credential without using it against production systems.",
        "Rotate the credential and check audit logs for historical use.",
      ],
      proofOfConcept:
        "grep -R \"REDACTED_SECRET_PATTERN\" .\n# Do not execute or validate real credentials against production services.",
      expectedVulnerableBehavior:
        "The repository or build artifact contains a reusable secret rather than a reference to a secure runtime secret.",
      businessImpact:
        "Credential exposure can lead to unauthorized service access, data theft, cloud resource abuse, and incident response costs.",
      secureFixExplanation:
        "Revoke and rotate the secret, remove it from source history where practical, and load replacement values from a secret manager.",
      secureCodeExample:
        "const apiKey = process.env.SERVICE_API_KEY;\nif (!apiKey) throw new Error('SERVICE_API_KEY is required');",
      securityTests:
        "expect(process.env.SERVICE_API_KEY).toBeDefined();\nexpect(sourceCode).not.toMatch(/AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]+/);",
      regressionPrevention:
        "Run secret scanning in pre-commit and CI, require secret rotation playbooks, and block commits containing credential patterns.",
      attackPreconditions: {
        ...common.attackPreconditions,
        authenticationRequired:
          "No application authentication is needed if the attacker can access the source, artifact, or logs containing the secret.",
        sensitiveDataExposure:
          "Likely, depending on the exposed credential's service scopes.",
      },
    }),
    dependency: template({
      lineReason:
        "The manifest pins or allows a package version with a known vulnerability advisory.",
      rootCause:
        "The project depends on a vulnerable version and has not upgraded to a patched release.",
      realWorldAttackScenario:
        "An attacker exploits the vulnerable library through any reachable feature that uses the affected package.",
      advancedAttackerReasoning:
        "The attacker fingerprints the dependency version from behavior, lockfiles, errors, or public metadata, then uses the published advisory to target the exploitable code path.",
      stepsToReproduce: [
        `Open the dependency declaration at ${location}.`,
        `Confirm ${packageName}${packageVersion ? `@${packageVersion}` : ""} is installed.`,
        "Review the linked advisory and execute only the advisory's non-destructive validation steps in a test environment.",
      ],
      proofOfConcept: `npm ls ${packageName}\n# Upgrade target: ${fixVersion || "latest patched version"}`,
      expectedVulnerableBehavior:
        "The dependency graph resolves to a version listed as affected by the vulnerability database.",
      businessImpact:
        "Known vulnerable dependencies increase exploitability because attackers can reuse public advisories and exploit techniques.",
      secureFixExplanation:
        fixVersion
          ? `Upgrade ${packageName} to ${fixVersion} or later and regenerate the lockfile.`
          : `Upgrade ${packageName} to a patched version and regenerate the lockfile.`,
      secureCodeExample: `npm install ${packageName}@${fixVersion || "latest"}`,
      securityTests: `npm audit --production\nnpm ls ${packageName}`,
      regressionPrevention:
        "Enable automated dependency updates, keep lockfiles committed, and fail CI when critical or high advisories are introduced.",
      attackPreconditions: common.attackPreconditions,
    }),
    "supply-chain": template({
      lineReason:
        "The dependency or install script has characteristics associated with malicious or suspicious package behavior.",
      rootCause:
        "The package trust boundary relies on external registry content without sufficient provenance, age, maintainer, or script review.",
      realWorldAttackScenario:
        "A malicious package runs during install or application startup and exfiltrates secrets from developer machines or CI runners.",
      advancedAttackerReasoning:
        "The attacker targets dependency confusion, typosquatting, or install hooks because package installation often has access to source, tokens, and build credentials.",
      stepsToReproduce: [
        `Review the package declaration or script at ${location}.`,
        "Inspect package metadata, maintainer history, repository link, and install scripts.",
        "Install only in an isolated disposable environment if dynamic validation is required.",
      ],
      proofOfConcept:
        "npm view <package> scripts repository maintainers\n# Run dynamic checks only in an isolated sandbox.",
      expectedVulnerableBehavior:
        "The project trusts package code or install scripts that may execute with developer or CI privileges.",
      businessImpact:
        "Supply-chain compromise can leak CI secrets, publish poisoned artifacts, and spread to downstream customers.",
      secureFixExplanation:
        "Remove suspicious packages, replace with verified alternatives, pin trusted versions, and require registry provenance checks.",
      secureCodeExample:
        "# package.json\n{\n  \"dependencies\": {\n    \"verified-package\": \"1.2.3\"\n  }\n}",
      securityTests:
        "npm ci --ignore-scripts\nnpm audit --production\nnpm ls suspicious-package",
      regressionPrevention:
        "Use lockfile review, private registry allowlists, package provenance checks, and CI installs with restricted tokens.",
      attackPreconditions: {
        ...common.attackPreconditions,
        authenticationRequired:
          "No application authentication is needed; compromise happens through dependency installation or runtime loading.",
      },
    }),
    iac: template({
      lineReason:
        "The configuration line weakens the runtime, network, identity, or deployment security boundary.",
      rootCause:
        "Infrastructure configuration grants broader access or exposure than the workload requires.",
      realWorldAttackScenario:
        "An attacker abuses the misconfiguration after gaining any foothold, or directly if the configuration exposes a service publicly.",
      advancedAttackerReasoning:
        "The attacker enumerates exposed ports, identities, mounted secrets, or container privileges, then pivots from the workload to infrastructure resources.",
      stepsToReproduce: [
        `Review the IaC resource at ${location}.`,
        "Deploy or validate the configuration in a non-production environment.",
        "Confirm the risky permission, exposure, or runtime option is present.",
      ],
      proofOfConcept:
        "terraform plan\n# or\nkubectl auth can-i --list --as=system:serviceaccount:namespace:name",
      expectedVulnerableBehavior:
        "The deployed resource has excessive exposure, privileges, or missing isolation controls.",
      businessImpact:
        "Infrastructure misconfiguration can expose services, widen blast radius, or allow lateral movement from one workload to another.",
      secureFixExplanation:
        "Apply least privilege, restrict network exposure, remove dangerous runtime options, and enforce secure defaults through policy-as-code.",
      secureCodeExample:
        "securityContext:\n  runAsNonRoot: true\n  allowPrivilegeEscalation: false\n  readOnlyRootFilesystem: true",
      securityTests:
        "checkov -d .\ntrivy config .\nkubectl apply --dry-run=server -f deployment.yaml",
      regressionPrevention:
        "Gate infrastructure changes with IaC scanning and policy-as-code checks before merge and deployment.",
      attackPreconditions: common.attackPreconditions,
    }),
    generic: template({
      lineReason:
        "The line matches a security rule that indicates unsafe data handling or weakened security controls.",
      rootCause:
        finding.description ||
        "The code violates a security invariant and should be reviewed in its surrounding data flow.",
      realWorldAttackScenario:
        "An attacker reaches the affected code path with crafted input or operational access and abuses the weakened control.",
      advancedAttackerReasoning:
        "The attacker determines the required input, state, or permission boundary, then combines this weakness with reachable application behavior.",
      stepsToReproduce: [
        `Review the code path at ${location}.`,
        "Identify the external input or configuration that reaches this line.",
        "Submit a safe boundary-value test and compare behavior against the intended security control.",
      ],
      proofOfConcept:
        "# Replace with a safe local request for the affected endpoint or CLI path.\ncurl -X POST http://localhost:3000/example -d '{}'",
      expectedVulnerableBehavior:
        "The application accepts unsafe input, exposes sensitive behavior, or bypasses an expected security check.",
      businessImpact:
        "The issue can weaken application security and may become more severe when chained with adjacent vulnerabilities.",
      secureFixExplanation:
        "Enforce the missing security control at the trust boundary and add tests that exercise malicious input.",
      secureCodeExample:
        "// Validate input, enforce authorization, and call a safe API before processing untrusted data.",
      securityTests:
        "expect(response.status).not.toBe(500);\nexpect(securityControl).toHaveBeenCalled();",
      regressionPrevention:
        "Add targeted unit/integration tests, keep scanner rules enabled, and require review for changes to this trust boundary.",
      attackPreconditions: common.attackPreconditions,
    }),
  };

  return templates[category] || templates.generic;
}

function template(
  value: Omit<
    VulnerabilityReportDetails,
    | "vulnerabilityName"
    | "severity"
    | "confidenceLevel"
    | "confidenceScore"
    | "affectedFilePath"
    | "affectedFunction"
    | "exactLineNumber"
    | "lineRange"
    | "language"
    | "vulnerableSourceCode"
    | "lineByLineExplanation"
  > & { lineReason: string },
) {
  return value;
}

function normalizeSeverity(severity: string): ReportSeverity {
  const upper = severity.toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(upper)) {
    return upper as ReportSeverity;
  }
  return "MEDIUM";
}

function normalizeConfidenceScore(confidence?: number | null): number | undefined {
  if (confidence == null || Number.isNaN(confidence)) return undefined;
  return confidence <= 1 ? Math.round(confidence * 100) : Math.round(confidence);
}

function formatConfidence(confidence?: number | null): string {
  const score = normalizeConfidenceScore(confidence);
  if (score == null) return "Not provided";
  if (score >= 90) return `${score}% - Very high`;
  if (score >= 75) return `${score}% - High`;
  if (score >= 50) return `${score}% - Medium`;
  return `${score}% - Low`;
}

function formatLineRange(
  startLine?: number | null,
  endLine?: number | null,
): string {
  if (!startLine) return "Line unavailable";
  if (!endLine || endLine === startLine) return `${startLine}`;
  return `${startLine}-${endLine}`;
}

function formatLocation(finding: ReportFindingInput): string {
  const file = finding.filePath || "the affected dependency or code path";
  return `${file}${finding.startLine ? `:${finding.startLine}` : ""}`;
}

function getOverallRiskRating(counts: {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}): SecurityScanReport["executiveSummary"]["overallRiskRating"] {
  if (counts.criticalCount > 0) return "Critical";
  if (counts.highCount > 0) return "High";
  if (counts.mediumCount > 0) return "Medium";
  if (counts.lowCount > 0) return "Low";
  return "Informational";
}

function languageFromFilePath(filePath?: string | null): string {
  if (!filePath) return "text";
  const basename = path.basename(filePath).toLowerCase();
  if (basename === "dockerfile" || basename.startsWith("dockerfile")) return "dockerfile";
  const ext = path.extname(filePath).toLowerCase();
  const map: Record<string, string> = {
    ".js": "javascript",
    ".jsx": "jsx",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".cs": "csharp",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".xml": "xml",
    ".tf": "hcl",
    ".sh": "bash",
    ".sql": "sql",
    ".md": "markdown",
  };
  return map[ext] || "text";
}

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function getString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function getStringField(
  finding: ReportFindingInput,
  key: string,
): string | undefined {
  const value = (finding as unknown as Record<string, unknown>)[key];
  return getString(value);
}

/** Prefer bullets for prose test plans; fenced block only for obvious code/shell. */
function markdownSecurityTestsBlock(raw: string): string[] {
  const t = raw.trim();
  if (!t) return ["_(None provided)_"];
  const codeLike =
    /^\s*(curl|wget|\$ |#!\/|import |export |const |function |def |class |describe\(|it\(|expect\()/im.test(
      t,
    ) || (t.includes("{") && t.includes("}") && t.length > 120);
  if (codeLike) {
    return ["```typescript", escapeMarkdownFence(raw), "```"];
  }
  const lines = t.split(/\n/).map((l) => l.trim()).filter(Boolean);
  return lines.map((line) => {
    if (/^[-*•]\s+/.test(line) || /^\d+[.)]\s+/.test(line)) return line;
    return `- ${line}`;
  });
}

function escapeMarkdownFence(value: string): string {
  return value.replace(/```/g, "'''");
}

function stripUndefined(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(stripUndefined);
  }
  if (!value || typeof value !== "object") return value;

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([, entry]) => entry !== undefined)
      .map(([key, entry]) => [key, stripUndefined(entry)]),
  );
}
