import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  buildSecurityScanReport,
  enrichRawFindingsWithSource,
  renderSecurityScanReportMarkdown,
  type ReportFindingInput,
} from "./security-report";

test("enrichRawFindingsWithSource captures source lines and function names", async () => {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-report-"));
  const filePath = "src/users.ts";
  fs.mkdirSync(path.join(workDir, "src"), { recursive: true });
  fs.writeFileSync(
    path.join(workDir, filePath),
    [
      "export async function searchUsers(email: string) {",
      '  const sql = "SELECT * FROM users WHERE email = \'" + email + "\'";',
      "  return db.query(sql);",
      "}",
    ].join("\n"),
  );

  const [finding] = await enrichRawFindingsWithSource<ReportFindingInput>(
    [
      {
        scanner: "SAST_PATTERN",
        severity: "HIGH",
        title: "SQL query with string concatenation",
        description: "Building SQL queries with string concatenation is unsafe.",
        filePath,
        startLine: 2,
        endLine: 2,
        ruleId: "JS-SQL-001",
        cweId: "CWE-89",
        confidence: 0.9,
      },
    ],
    workDir,
  );

  const report = (
    finding.metadata as {
      report: {
        affectedFunction: string;
        exactLineNumber: number;
        vulnerableSourceCode: string;
        lineByLineExplanation: Array<{
          lineNumber?: number;
          explanation: string;
        }>;
      };
    }
  ).report;
  assert.equal(report.affectedFunction, "searchUsers");
  assert.equal(report.exactLineNumber, 2);
  assert.match(report.vulnerableSourceCode, /2:   const sql/);
  assert.ok(
    report.lineByLineExplanation.some(
      (line) =>
        line.lineNumber === 2 &&
        line.explanation.includes("attacker-controlled"),
    ),
  );
});

test("buildSecurityScanReport groups severities and emits risk rating", () => {
  const report = buildSecurityScanReport({
    scanId: "scan-1",
    projectName: "Payments API",
    findings: [
      {
        id: "f1",
        scanner: "SAST_PATTERN",
        severity: "CRITICAL",
        title: "Command injection via child_process",
        description: "User input reaches exec.",
        filePath: "src/tasks.ts",
        startLine: 12,
        cweId: "CWE-78",
        confidence: 0.95,
      },
      {
        id: "f2",
        scanner: "SCA",
        severity: "MEDIUM",
        title: "Vulnerable dependency",
        description: "Package has an advisory.",
        metadata: { packageName: "example-lib", fixVersion: "2.0.0" },
        confidence: 1,
      },
    ],
    generatedAt: "2026-04-29T00:00:00.000Z",
  });

  assert.equal(report.executiveSummary.totalVulnerabilities, 2);
  assert.equal(report.executiveSummary.criticalCount, 1);
  assert.equal(report.executiveSummary.mediumCount, 1);
  assert.equal(report.executiveSummary.infoCount, 0);
  assert.equal(report.executiveSummary.overallRiskRating, "Critical");
  assert.equal(report.vulnerabilities[0].report.severity, "CRITICAL");
});

test("buildSecurityScanReport merges sparse LLM report with template fallbacks", () => {
  const report = buildSecurityScanReport({
    findings: [
      {
        id: "llm-1",
        scanner: "SAST_LLM",
        severity: "HIGH",
        title: "SQL injection risk",
        description: "Narrative from the scanner that should appear on the vulnerability record.",
        filePath: "src/api.ts",
        startLine: 10,
        cweId: "CWE-89",
        confidence: 0.88,
        metadata: {
          report: {
            vulnerabilityName: "SQL injection risk",
            severity: "HIGH",
            rootCause: "",
            realWorldAttackScenario: "Custom concrete scenario from the model.",
            lineByLineExplanation: [],
            stepsToReproduce: [],
            attackPreconditions: {},
            proofOfConcept: "",
            businessImpact: "",
            secureFixExplanation: "",
            secureCodeExample: "",
            securityTests: "",
            regressionPrevention: "",
            advancedAttackerReasoning: "",
            expectedVulnerableBehavior: "",
            affectedFilePath: "",
            affectedFunction: "",
            lineRange: "",
            language: "",
            vulnerableSourceCode: "",
            confidenceLevel: "",
          },
        },
      },
    ],
  });

  const v = report.vulnerabilities[0].report;
  assert.ok(
    v.rootCause.length > 20,
    "empty LLM rootCause should be filled from template",
  );
  assert.match(v.realWorldAttackScenario, /Custom concrete scenario/);
  assert.ok(
    report.vulnerabilities[0].scannerDescription?.includes("Narrative"),
  );
});

test("executive summary counts INFO severities", () => {
  const report = buildSecurityScanReport({
    findings: [
      {
        scanner: "SAST_PATTERN",
        severity: "INFO",
        title: "Informational note",
        description: "FYI",
        filePath: "readme.md",
        startLine: 1,
      },
    ],
  });
  assert.equal(report.executiveSummary.infoCount, 1);
  assert.equal(report.executiveSummary.overallRiskRating, "Informational");
});

test("markdown report includes developer-ready sections", () => {
  const report = buildSecurityScanReport({
    findings: [
      {
        scanner: "SECRETS_PATTERN",
        severity: "HIGH",
        title: "Hardcoded API key",
        description: "A credential was found in source.",
        filePath: "src/config.ts",
        startLine: 4,
        snippet: "4: const apiKey = '[MASKED]';",
        cweId: "CWE-798",
        confidence: 0.85,
        masked: true,
      },
    ],
    generatedAt: "2026-04-29T00:00:00.000Z",
  });

  const markdown = renderSecurityScanReportMarkdown(report);
  assert.match(markdown, /# Security Scan Report/);
  assert.match(markdown, /## Executive Summary/);
  assert.match(markdown, /#### Steps to Reproduce/);
  assert.match(markdown, /#### Security Tests/);
  assert.doesNotMatch(markdown, /localhost\/example/);
  assert.doesNotMatch(markdown, /file\.txt;\s*whoami/);
});

test("report JSON includes reproduction and fix guidance", () => {
  const report = buildSecurityScanReport({
    findings: [
      {
        scanner: "SCA",
        severity: "HIGH",
        title: "GHSA-test: Vulnerability in express",
        description: "Package: express@4.0.0 (npm)",
        filePath: "package.json",
        startLine: 10,
        metadata: {
          packageName: "express",
          packageVersion: "4.0.0",
          fixVersion: "4.18.3",
        },
        confidence: 1,
      },
    ],
  });

  const detail = report.vulnerabilities[0].report;
  assert.equal(detail.proofOfConcept, "");
  assert.match(detail.secureFixExplanation, /4.18.3/);
  assert.doesNotThrow(() => JSON.stringify(report));
});
