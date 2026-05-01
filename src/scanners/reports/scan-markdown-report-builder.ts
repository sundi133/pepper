import type { RawFinding } from "@/scanners/types";
import { generateFindingReport } from "./finding-report-generator";

export type ScanLike = {
  id?: string;
  scanType?: string;
  sourceType?: string | null;
  sourceRef?: string | null;
  branch?: string | null;
  commitSha?: string | null;
};

export type ProjectLike = {
  name?: string;
  repoUrl?: string | null;
};

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export function buildScanMarkdownReport(input: {
  scan: ScanLike;
  project?: ProjectLike;
  findings: RawFinding[];
}): string {
  const lines: string[] = ["# SAST Findings Report", ""];
  if (input.project?.name) lines.push(`**Project:** ${input.project.name}`);
  if (input.scan.id) lines.push(`**Scan ID:** \`${input.scan.id}\``);
  if (input.scan.scanType) lines.push(`**Scan type:** \`${input.scan.scanType}\``);
  if (input.scan.branch) lines.push(`**Branch:** \`${input.scan.branch}\``);
  if (input.scan.commitSha) lines.push(`**Commit:** \`${input.scan.commitSha}\``);
  if (input.scan.sourceRef) lines.push(`**Source:** \`${input.scan.sourceRef}\``);
  if (lines.length > 2) lines.push("");

  const findings = [...input.findings].sort(
    (a, b) =>
      SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
      (a.filePath || "").localeCompare(b.filePath || "") ||
      (a.startLine || 0) - (b.startLine || 0),
  );

  if (findings.length === 0) {
    lines.push("No findings were reported by the enabled scanners.");
    lines.push("");
  } else {
    for (const finding of findings) {
      const report = generateFindingReport({
        finding,
        scan: input.scan,
        project: input.project,
        allFindings: findings.length === 1 ? findings : undefined,
      }).markdown;
      if (findings.length === 1) {
        lines.push(report);
      } else {
        lines.push(stripSummary(report));
      }
      lines.push("");
    }
  }

  if (findings.length !== 1) {
    lines.push("## Summary");
    lines.push("");
    lines.push(summaryTable(findings));
    lines.push("");
    lines.push(`**Overall risk:** ${overallRisk(findings)}.`);
    lines.push(finalRiskSentence(findings));
  }

  return lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd() + "\n";
}

function stripSummary(markdown: string): string {
  return markdown.replace(/\n## Summary[\s\S]*$/m, "").trimEnd();
}

function summaryTable(findings: RawFinding[]): string {
  const counts = new Map<string, number>();
  for (const severity of SEVERITIES) counts.set(severity, 0);
  for (const finding of findings) counts.set(finding.severity, (counts.get(finding.severity) || 0) + 1);
  return [
    "| Severity | Count |",
    "| -------- | ----: |",
    `| Critical | ${String(counts.get("CRITICAL") || 0).padStart(5)} |`,
    `| High     | ${String(counts.get("HIGH") || 0).padStart(5)} |`,
    `| Medium   | ${String(counts.get("MEDIUM") || 0).padStart(5)} |`,
    `| Low      | ${String(counts.get("LOW") || 0).padStart(5)} |`,
    `| Info     | ${String(counts.get("INFO") || 0).padStart(5)} |`,
  ].join("\n");
}

function overallRisk(findings: RawFinding[]): string {
  for (const severity of SEVERITIES) {
    if (findings.some((finding) => finding.severity === severity)) {
      return severity === "INFO" ? "Informational" : severity[0] + severity.slice(1).toLowerCase();
    }
  }
  return "Informational";
}

function finalRiskSentence(findings: RawFinding[]): string {
  const risk = overallRisk(findings);
  if (risk === "Critical" || risk === "High") return "Fix the highest-risk confirmed findings first, then rerun the scan.";
  if (risk === "Medium") return "Address confirmed issues before release and add regression coverage.";
  if (findings.length === 0) return "No scanner findings were reported for this scan.";
  return "Review low and informational findings as part of normal hardening.";
}
