/**
 * Auto-Scan Agent for Pepper
 * 
 * Orchestrates all scanner modules (SAST, SCA, IaC, Secrets, Container, Zero-Day)
 * and generates LLM prompts for analysis, remediation, and compliance mapping.
 * 
 * Usage:
 *   const agent = new AutoScanAgent(scanContext);
 *   const results = await agent.runFullScan();
 *   const report = await agent.generateReport(results);
 */

import { ScanContext, RawFinding } from "./types";
import { logger } from "@/lib/logger";
import { prisma } from "@/lib/prisma";

interface ScannerModule {
  name: string;
  enabled: boolean;
  scan: (ctx: ScanContext) => Promise<RawFinding[]>;
}

interface AutoScanResult {
  scanId?: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  findings: RawFinding[];
  scannerMetrics: Record<string, ScannerMetrics>;
  summary: ScanSummary;
  prompts: GeneratedPrompts;
}

interface ScannerMetrics {
  name: string;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  duration: number;
  status: "success" | "failed" | "skipped";
  error?: string;
}

interface ScanSummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  scannersSummary: Record<string, string>;
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  remediationEstimate: {
    phase1Hours: number;
    phase2Hours: number;
    phase3Hours: number;
  };
}

interface GeneratedPrompts {
  executiveSummary: string;
  remediationGuide: string;
  complianceMapping: string;
  cicdIntegration: string;
  deploymentReadiness: string;
}

export class AutoScanAgent {
  private ctx: ScanContext;
  private scanners: ScannerModule[] = [];

  constructor(ctx: ScanContext) {
    this.ctx = ctx;
    this.initializeScanners();
  }

  private initializeScanners() {
    // Dynamically load scanner modules
    this.scanners = [
      {
        name: "SAST_LLM",
        enabled: this.ctx.orgSettings.enableLlmSast,
        scan: (ctx) => this.runSastScanner(ctx),
      },
      {
        name: "SCA",
        enabled: true,
        scan: (ctx) => this.runScaScanner(ctx),
      },
      {
        name: "SECRETS",
        enabled: this.ctx.orgSettings.enableLlmSecrets,
        scan: (ctx) => this.runSecretsScanner(ctx),
      },
      {
        name: "IAC",
        enabled: this.ctx.orgSettings.enableLlmSast,
        scan: (ctx) => this.runIacScanner(ctx),
      },
      {
        name: "CONTAINER",
        enabled: true,
        scan: (ctx) => this.runContainerScanner(ctx),
      },
      {
        name: "ZERO_DAY",
        enabled: this.ctx.orgSettings.enableLlmSast,
        scan: (ctx) => this.runZeroDayScanner(ctx),
      },
    ];
  }

  /**
   * Run full DevSecOps scan across all enabled modules
   */
  async runFullScan(): Promise<AutoScanResult> {
    const startTime = new Date();
    const allFindings: RawFinding[] = [];
    const scannerMetrics: Record<string, ScannerMetrics> = {};

    logger.info({ scanId: this.ctx.scanId }, "Starting auto-scan across all modules");

    for (const scanner of this.scanners) {
      if (!scanner.enabled) {
        scannerMetrics[scanner.name] = {
          name: scanner.name,
          findings: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          duration: 0,
          status: "skipped",
        };
        continue;
      }

      const scanStartTime = Date.now();

      try {
        this.ctx.onProgress?.(`Scanning with ${scanner.name}...`);

        const findings = await scanner.scan(this.ctx);
        const duration = Date.now() - scanStartTime;

        const metrics = this.calculateMetrics(scanner.name, findings);
        scannerMetrics[scanner.name] = { ...metrics, duration, status: "success" };

        allFindings.push(...findings);

        logger.info(
          { scanner: scanner.name, count: findings.length, duration },
          "Scanner completed successfully"
        );
      } catch (error) {
        const duration = Date.now() - scanStartTime;
        scannerMetrics[scanner.name] = {
          name: scanner.name,
          findings: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          duration,
          status: "failed",
          error: error instanceof Error ? error.message : "Unknown error",
        };

        logger.error(
          { scanner: scanner.name, error },
          "Scanner failed"
        );
      }
    }

    const endTime = new Date();
    const duration = endTime.getTime() - startTime.getTime();

    // Generate summary and prompts
    const summary = this.generateSummary(allFindings, scannerMetrics);
    const prompts = await this.generatePrompts(allFindings, summary);

    return {
      scanId: this.ctx.scanId,
      startTime,
      endTime,
      duration,
      findings: allFindings,
      scannerMetrics,
      summary,
      prompts,
    };
  }

  /**
   * Calculate metrics for a scanner's findings
   */
  private calculateMetrics(scanner: string, findings: RawFinding[]): Omit<ScannerMetrics, "duration" | "status" | "error"> {
    const critical = findings.filter((f) => f.severity === "CRITICAL").length;
    const high = findings.filter((f) => f.severity === "HIGH").length;
    const medium = findings.filter((f) => f.severity === "MEDIUM").length;
    const low = findings.filter((f) => f.severity === "LOW").length;

    return {
      name: scanner,
      findings: findings.length,
      critical,
      high,
      medium,
      low,
    };
  }

  /**
   * Generate scan summary with risk assessment
   */
  private generateSummary(
    findings: RawFinding[],
    metrics: Record<string, ScannerMetrics>
  ): ScanSummary {
    const critical = findings.filter((f) => f.severity === "CRITICAL").length;
    const high = findings.filter((f) => f.severity === "HIGH").length;
    const medium = findings.filter((f) => f.severity === "MEDIUM").length;
    const low = findings.filter((f) => f.severity === "LOW").length;

    // Determine risk level
    let riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" = "LOW";
    if (critical > 0) riskLevel = "CRITICAL";
    else if (high > 2) riskLevel = "HIGH";
    else if (medium > 5) riskLevel = "MEDIUM";

    // Generate scanner summary
    const scannersSummary: Record<string, string> = {};
    for (const [name, metric] of Object.entries(metrics)) {
      if (metric.status === "skipped") {
        scannersSummary[name] = "Skipped";
      } else if (metric.status === "failed") {
        scannersSummary[name] = `Failed: ${metric.error}`;
      } else {
        scannersSummary[name] = `${metric.findings} findings (${metric.critical} CRITICAL, ${metric.high} HIGH)`;
      }
    }

    // Estimate remediation time
    const remediationEstimate = {
      phase1Hours: Math.ceil(critical * 0.5 + high * 0.25),
      phase2Hours: Math.ceil(medium * 0.5),
      phase3Hours: Math.ceil(low * 0.25),
    };

    return {
      totalFindings: findings.length,
      criticalCount: critical,
      highCount: high,
      mediumCount: medium,
      lowCount: low,
      scannersSummary,
      riskLevel,
      remediationEstimate,
    };
  }

  /**
   * Generate LLM prompts for various use cases
   */
  private async generatePrompts(
    findings: RawFinding[],
    summary: ScanSummary
  ): Promise<GeneratedPrompts> {
    const findingsByScanner = this.groupFindingsByScanner(findings);

    return {
      executiveSummary: this.generateExecutiveSummaryPrompt(findings, summary),
      remediationGuide: this.generateRemediationPrompt(findings, findingsByScanner),
      complianceMapping: this.generateCompliancePrompt(findings),
      cicdIntegration: this.generateCicdPrompt(findings, summary),
      deploymentReadiness: this.generateDeploymentPrompt(findings, summary),
    };
  }

  /**
   * Generate prompt for executive summary
   */
  private generateExecutiveSummaryPrompt(
    findings: RawFinding[],
    summary: ScanSummary
  ): string {
    const criticalFindings = findings
      .filter((f) => f.severity === "CRITICAL")
      .slice(0, 5);

    return `
Generate a professional executive summary for a DevSecOps security scan with the following results:

**Scan Overview:**
- Total Findings: ${summary.totalFindings}
- CRITICAL: ${summary.criticalCount}
- HIGH: ${summary.highCount}
- MEDIUM: ${summary.mediumCount}
- LOW: ${summary.lowCount}
- Risk Level: ${summary.riskLevel}

**Top Critical Findings:**
${criticalFindings.map((f, i) => `${i + 1}. ${f.title} (${f.cweId}): ${f.description?.slice(0, 100)}`).join("\n")}

**Scanner Results:**
${Object.entries(summary.scannersSummary).map(([name, result]) => `- ${name}: ${result}`).join("\n")}

**Remediation Timeline:**
- Phase 1 (CRITICAL): ${summary.remediationEstimate.phase1Hours} hours
- Phase 2 (HIGH): ${summary.remediationEstimate.phase2Hours} hours
- Phase 3 (MEDIUM/LOW): ${summary.remediationEstimate.phase3Hours} hours

Generate a concise (300-400 word) executive summary that:
1. States the overall security posture clearly
2. Highlights the top 3 risks and their business impact
3. Provides a remediation timeline
4. Recommends next steps for deployment

Format as markdown suitable for C-level stakeholders.`;
  }

  /**
   * Generate prompt for remediation guide
   */
  private generateRemediationPrompt(
    findings: RawFinding[],
    findingsByScanner: Record<string, RawFinding[]>
  ): string {
    const criticalAndHigh = findings.filter((f) =>
      ["CRITICAL", "HIGH"].includes(f.severity)
    );

    return `
Generate a detailed remediation guide for the following security findings:

**CRITICAL and HIGH Severity Issues:**
${criticalAndHigh
  .map(
    (f) => `
- Title: ${f.title}
- File: ${f.filePath}
- Lines: ${f.startLine}-${f.endLine}
- Description: ${f.description}
- CWE: ${f.cweId}
`
  )
  .join("\n")}

**Remediation Guide Requirements:**
1. For each finding, provide:
   - Root cause explanation
   - Step-by-step fix instructions
   - Before/after code comparison
   - Testing instructions
   - Verification commands

2. Group fixes by type:
   - Code vulnerabilities
   - Dependency updates
   - Configuration changes
   - Container/IaC improvements

3. Include:
   - Implementation checklist
   - Time estimates per fix
   - Risk assessment (won't fix → reduce scope)
   - Automated test cases

4. Format with clear sections, code blocks, and priority levels

Generate a comprehensive remediation guide suitable for developers to implement.`;
  }

  /**
   * Generate prompt for compliance mapping
   */
  private generateCompliancePrompt(findings: RawFinding[]): string {
    const cweIds = [...new Set(findings.map((f) => f.cweId).filter(Boolean))];
    const severities = [...new Set(findings.map((f) => f.severity))];

    return `
Map the following security findings to compliance standards:

**Findings Summary:**
- Total: ${findings.length}
- CWE IDs: ${cweIds.join(", ")}
- Severity Levels: ${severities.join(", ")}

**Finding Details:**
${findings
  .slice(0, 20)
  .map(
    (f) => `
- ${f.title}
  CWE: ${f.cweId}
  Severity: ${f.severity}
  File: ${f.filePath}
`
  )
  .join("\n")}

Generate a compliance mapping report that includes:

1. **OWASP Top 10 2021 Mapping:**
   - Map each finding to relevant OWASP category
   - Provide remediation guidance per OWASP

2. **CWE Mapping:**
   - List all CWE IDs identified
   - Describe each weakness
   - Show remediation approaches

3. **CVSS Scoring:**
   - Calculate base CVSS scores
   - Provide severity explanations
   - Recommend risk acceptance criteria

4. **Compliance Standards:**
   - PCI-DSS requirements affected
   - HIPAA implications (if applicable)
   - SOC 2 controls required
   - ISO 27001 mapping

5. **Risk Assessment:**
   - Business impact analysis
   - Likelihood vs. impact matrix
   - Risk acceptance threshold

Format as a structured compliance report with tables and clear risk ratings.`;
  }

  /**
   * Generate prompt for CI/CD integration
   */
  private generateCicdPrompt(findings: RawFinding[], summary: ScanSummary): string {
    return `
Generate CI/CD pipeline configuration for automated security scanning:

**Current Scan Results:**
- CRITICAL: ${summary.criticalCount}
- HIGH: ${summary.highCount}
- MEDIUM: ${summary.mediumCount}
- LOW: ${summary.lowCount}

**Pipeline Requirements:**
1. GitHub Actions workflow that:
   - Runs on push and pull requests
   - Executes all 6 scanner modules (SAST, SCA, IaC, Secrets, Container, Zero-Day)
   - Blocks merge if CRITICAL findings exist
   - Warns on HIGH severity
   - Generates reports and artifacts

2. Scan gates (fail conditions):
   - Any CRITICAL findings block deployment
   - More than 5 HIGH findings block deployment
   - Unresolved secrets block deployment
   - Outdated base images warn but don't block

3. Reporting:
   - Generate HTML report
   - Create SARIF format for GitHub
   - Post results to pull request
   - Archive reports

4. Notifications:
   - Slack alerts for CRITICAL
   - Email summary to security team
   - Dashboard integration

5. Integration with:
   - Dependabot for dependency updates
   - Snyk for SCA
   - TruffleHog for secrets
   - Trivy for container images
   - SonarQube for code quality

Generate complete workflow files (YAML) for GitHub Actions with:
- Job definitions for each scanner
- Artifact uploads
- Status checks
- Report generation
- Notification logic

Make it production-ready and best-practice compliant.`;
  }

  /**
   * Generate prompt for deployment readiness
   */
  private generateDeploymentPrompt(
    findings: RawFinding[],
    summary: ScanSummary
  ): string {
    const blockers = findings.filter((f) => f.severity === "CRITICAL");
    const warnings = findings.filter((f) => f.severity === "HIGH");

    return `
Assess deployment readiness based on security scan results:

**Current Status:**
- CRITICAL Blockers: ${blockers.length}
- HIGH Warnings: ${warnings.length}
- Risk Level: ${summary.riskLevel}

**Critical Blockers:**
${blockers.slice(0, 10).map((f) => `- ${f.title} (${f.filePath}:${f.startLine})`).join("\n")}

**High Warnings:**
${warnings.slice(0, 10).map((f) => `- ${f.title} (${f.filePath}:${f.startLine})`).join("\n")}

Generate a deployment readiness assessment that includes:

1. **Deployment Status:**
   - BLOCKED / CONDITIONAL / APPROVED
   - Clear justification
   - Risk acceptance statement

2. **Release Notes:**
   - Security fixes included
   - Known limitations
   - Migration guidance if needed

3. **Post-Deployment:**
   - Monitoring recommendations
   - Security alert thresholds
   - Incident response procedures
   - Rollback criteria

4. **Sign-off Checklist:**
   - Security team approval needed
   - Legal/compliance review if applicable
   - Operations readiness
   - Documentation complete

5. **Risk Acceptance:**
   - For any CRITICAL findings not fixed:
     - Business justification
     - Mitigation controls
     - Timeline to resolve
     - Executive sign-off required

Generate a formal deployment readiness report suitable for release approval.`;
  }

  /**
   * Helper: Group findings by scanner
   */
  private groupFindingsByScanner(findings: RawFinding[]): Record<string, RawFinding[]> {
    const grouped: Record<string, RawFinding[]> = {};

    for (const finding of findings) {
      const scanner = finding.scanner || "UNKNOWN";
      if (!grouped[scanner]) grouped[scanner] = [];
      grouped[scanner].push(finding);
    }

    return grouped;
  }

  /**
   * Private scanner implementations (delegate to existing scanners)
   */
  private async runSastScanner(ctx: ScanContext): Promise<RawFinding[]> {
    const { runLlmSastScanner } = await import("./sast/llm-analyzer");
    return runLlmSastScanner(ctx);
  }

  private async runScaScanner(ctx: ScanContext): Promise<RawFinding[]> {
    const { scaScanner } = await import("./sca");
    return scaScanner.scan(ctx);
  }

  private async runSecretsScanner(ctx: ScanContext): Promise<RawFinding[]> {
    const { secretsLlmScanner } = await import("./secrets");
    return secretsLlmScanner.scan(ctx);
  }

  private async runIacScanner(ctx: ScanContext): Promise<RawFinding[]> {
    const { iacScanner } = await import("./iac");
    return iacScanner.scan(ctx);
  }

  private async runContainerScanner(ctx: ScanContext): Promise<RawFinding[]> {
    const { containerScanner } = await import("./container");
    return containerScanner.scan(ctx);
  }

  private async runZeroDayScanner(ctx: ScanContext): Promise<RawFinding[]> {
    const { zeroDayScanner } = await import("./zero-day");
    return zeroDayScanner.scan(ctx);
  }

  /**
   * Generate formatted report from scan results
   */
  async generateReport(result: AutoScanResult): Promise<string> {
    const report = `
# DevSecOps Scan Report
**Scan ID**: ${result.scanId}
**Date**: ${result.startTime.toISOString()}
**Duration**: ${(result.duration / 1000).toFixed(1)}s

## Executive Summary
${result.prompts.executiveSummary}

## Scanner Results
${this.formatScannerMetrics(result.scannerMetrics)}

## Critical Findings
${this.formatFindings(result.findings.filter((f) => f.severity === "CRITICAL"))}

## Remediation Guide
${result.prompts.remediationGuide}

## Compliance Mapping
${result.prompts.complianceMapping}

## CI/CD Integration
${result.prompts.cicdIntegration}

## Deployment Readiness
${result.prompts.deploymentReadiness}
`;

    return report;
  }

  private formatScannerMetrics(metrics: Record<string, ScannerMetrics>): string {
    return Object.entries(metrics)
      .map(([name, m]) => {
        if (m.status === "skipped") return `- ${name}: Skipped`;
        if (m.status === "failed") return `- ${name}: Failed - ${m.error}`;
        return `- ${name}: ${m.findings} findings (${m.critical} 🔴 ${m.high} 🟠 ${m.medium} 🟡 ${m.low} 🟢) [${m.duration}ms]`;
      })
      .join("\n");
  }

  private formatFindings(findings: RawFinding[]): string {
    return findings
      .slice(0, 10)
      .map(
        (f) => `
### ${f.title}
- **File**: ${f.filePath}:${f.startLine}
- **CWE**: ${f.cweId}
- **Confidence**: ${f.confidence}
- **Description**: ${f.description}
`
      )
      .join("\n");
  }
}

export default AutoScanAgent;
