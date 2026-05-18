import fs from "fs";
import os from "os";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { renderReportMarkdown, type StoredFindingReport } from "@/lib/finding-report";
import { RawFinding, SeverityLevel } from "../types";

const execFileP = promisify(execFile);

const DEFAULT_DAPPER_REPO_URL =
  "https://github.com/sundi133/dapper.git";
const DEFAULT_EXPORT_MODEL = "claude-opus-4-6";
const DEFAULT_EXPORT_MAX_TURNS = 100;
const DEFAULT_WORKSPACE_DIR = path.join(os.tmpdir(), "pepper-dapper");

export interface DapperWorkspaceResult {
  workflowId: string;
  repoName: string;
  workspaceRoot: string;
  deliverablesDir: string;
  findings: RawFinding[];
  developerReportMarkdown: string;
  executiveReportMarkdown: string;
  exportJsonPath: string;
  exportCsvPath: string;
  artifact: unknown;
}

interface ExportedFinding {
  id?: string;
  type?: string;
  title?: string;
  severity?: string;
  status?: string;
  likelihood?: string;
  impact_level?: string;
  risk_score?: number;
  source_endpoint?: string;
  affected_endpoint?: string;
  parameter?: string;
  code_location?: string;
  missing_defense?: string;
  attack_path?: string;
  exploitation_hypothesis?: string;
  confidence?: number;
  externally_exploitable?: boolean;
  cwe?: string;
  cwe_names?: string;
  remediation_suggestions?: string;
  developer_verification_steps?: string[];
  estimated_annual_occurrence?: string;
  business_impact?: string;
  data_at_risk?: string;
  compliance_impact?: string;
  attack_chain_id?: string;
  attack_chain_role?: string;
  attack_chain_description?: string;
  chained_with?: string | string[];
  evidence_snippet?: string;
  exploit_result?: string;
  report_section?: string;
  source_file?: string | string[];
  notes?: string;
}

function mapSeverity(input?: string): SeverityLevel {
  switch ((input || "").trim().toUpperCase()) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MEDIUM":
    case "MODERATE":
      return "MEDIUM";
    case "LOW":
      return "LOW";
    default:
      return "INFO";
  }
}

function hasValue(value: unknown): boolean {
  return !(
    value === null ||
    value === undefined ||
    (typeof value === "string" && value.trim() === "") ||
    (Array.isArray(value) && value.length === 0)
  );
}

function normalizeMultiValue(value: unknown): string {
  if (!hasValue(value)) return "";
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean).join("; ");
  }
  return String(value);
}

function splitLines(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  if (typeof value === "string") {
    return value
      .split(/\r?\n|;\s*/)
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
}

function safeText(value: unknown): string {
  return hasValue(value) ? String(value).trim() : "";
}

function readJsonArray(filePath: string): ExportedFinding[] {
  if (!fs.existsSync(filePath)) return [];
  const raw = fs.readFileSync(filePath, "utf8").trim();
  if (!raw) return [];
  const cleaned = raw.replace(/^```json\s*/i, "").replace(/\s*```$/i, "");
  const parsed = JSON.parse(cleaned);
  return Array.isArray(parsed) ? (parsed as ExportedFinding[]) : [];
}

function buildStoredReport(finding: ExportedFinding): StoredFindingReport {
  const endpoint =
    safeText(finding.source_endpoint) || safeText(finding.affected_endpoint);
  const parameter = safeText(finding.parameter);
  const location = safeText(finding.code_location);
  const chain = safeText(finding.attack_chain_description);
  const summary = [
    safeText(finding.attack_path) ||
      safeText(finding.exploitation_hypothesis) ||
      safeText(finding.notes) ||
      safeText(finding.report_section) ||
      safeText(finding.type) ||
      safeText(finding.title),
    endpoint ? `Affected endpoint: ${endpoint}` : "",
    parameter ? `Parameter: ${parameter}` : "",
    chain ? `Attack chain: ${chain}` : "",
    location ? `Code location: ${location}` : "",
  ]
    .filter(Boolean)
    .join("\n\n");

  const remediation = splitLines(finding.remediation_suggestions);
  const steps = splitLines(finding.developer_verification_steps);
  const impact = [
    safeText(finding.business_impact),
    safeText(finding.data_at_risk),
    safeText(finding.compliance_impact),
  ]
    .filter(Boolean)
    .join("\n\n");

  const report: StoredFindingReport = {
    vulnerabilityName:
      safeText(finding.title) ||
      safeText(finding.type) ||
      safeText(finding.id) ||
      "DAST finding",
    summary,
    stepsToReproduce:
      steps.length > 0
        ? steps
        : [
            "Review the Dapper deliverables and reproduce the issue in a safe local or staging environment.",
            endpoint
              ? `Exercise the affected endpoint or workflow at ${endpoint}.`
              : "Exercise the affected endpoint or workflow identified in the Dapper report.",
          ],
    impact:
      impact ||
      "A reachable application weakness may permit unauthorized access, data exposure, or other business-impacting behavior.",
    remediation:
      remediation.length > 0
        ? remediation
        : [
            "Apply the missing server-side validation, authorization, or security control identified by Dapper.",
          ],
  };

  return report;
}

function buildRawFinding(
  finding: ExportedFinding,
  workflowId: string,
  repoName: string,
  target: string,
): RawFinding {
  const reportSections = buildStoredReport(finding);
  const reportMarkdown = renderReportMarkdown(reportSections);
  const filePath =
    normalizeMultiValue(finding.source_file) ||
    safeText(finding.source_endpoint) ||
    safeText(finding.affected_endpoint) ||
    safeText(finding.code_location) ||
    undefined;

  return {
    scanner: "DAST" as const,
    severity: mapSeverity(finding.severity),
    title:
      safeText(finding.title) ||
      safeText(finding.type) ||
      safeText(finding.id) ||
      "DAST finding",
    description:
      [
        safeText(finding.attack_path),
        safeText(finding.exploitation_hypothesis),
        safeText(finding.notes),
        safeText(finding.report_section),
      ]
        .filter(Boolean)
        .join("\n\n") ||
      safeText(finding.title) ||
      safeText(finding.type) ||
      "Dynamic application security testing finding",
    filePath,
    ruleId: safeText(finding.id) || safeText(finding.type) || undefined,
    cweId: safeText(finding.cwe) || undefined,
    confidence: typeof finding.confidence === "number" ? finding.confidence : 0.9,
    metadata: {
      workflowId,
      repoName,
      target,
      dapperExport: finding,
      reportVersion: 5,
      reportSections,
      reportMarkdown,
      source_endpoint: safeText(finding.source_endpoint) || undefined,
      affected_endpoint: safeText(finding.affected_endpoint) || undefined,
      parameter: safeText(finding.parameter) || undefined,
      attack_chain_id: safeText(finding.attack_chain_id) || undefined,
      attack_chain_role: safeText(finding.attack_chain_role) || undefined,
      attack_chain_description: safeText(finding.attack_chain_description) || undefined,
      chained_with: normalizeMultiValue(finding.chained_with) || undefined,
    },
  };
}

function resolveWorkspaceRoot(): string | undefined {
  const explicit = process.env.DAPPER_WORKSPACE_DIR || process.env.DAPPER_HOME;
  if (explicit && explicit.trim()) return path.resolve(explicit.trim());

  const sibling = path.resolve(process.cwd(), "..", "dapper");
  if (fs.existsSync(path.join(sibling, "dapper"))) return sibling;
  return undefined;
}

async function ensureWorkspaceRoot(
  workspaceRoot: string,
  onProgress?: (message: string) => void,
): Promise<void> {
  if (fs.existsSync(path.join(workspaceRoot, "dapper"))) return;

  const repoUrl =
    process.env.DAPPER_REPO_URL || DEFAULT_DAPPER_REPO_URL;
  onProgress?.(`DAST: cloning dapper into ${workspaceRoot}`);
  fs.mkdirSync(path.dirname(workspaceRoot), { recursive: true });
  await execFileP("git", ["clone", "--depth", "1", repoUrl, workspaceRoot], {
    timeout: 30 * 60 * 1000,
    maxBuffer: 16 * 1024 * 1024,
  });
}

async function stageTargetRepo(
  workspaceRoot: string,
  repoName: string,
  workDir: string,
): Promise<string> {
  const repoDir = path.join(workspaceRoot, "repos", repoName);
  fs.rmSync(repoDir, { recursive: true, force: true });
  fs.mkdirSync(repoDir, { recursive: true });
  fs.cpSync(workDir, repoDir, { recursive: true, force: true });
  fs.mkdirSync(path.join(repoDir, "deliverables"), { recursive: true });
  fs.chmodSync(path.join(repoDir, "deliverables"), 0o777);
  return repoDir;
}

async function prepareConfig(
  workspaceRoot: string,
): Promise<string | undefined> {
  const configPath = process.env.DAPPER_CONFIG_PATH;
  if (!configPath || !configPath.trim()) return undefined;

  const resolved = path.resolve(configPath.trim());
  if (!fs.existsSync(resolved)) {
    throw new Error(`Dapper config file not found: ${resolved}`);
  }

  const fileName = path.basename(resolved);
  const targetPath = path.join(workspaceRoot, "configs", fileName);
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.copyFileSync(resolved, targetPath);
  return `./configs/${fileName}`;
}

async function startWorkflow(
  workspaceRoot: string,
  target: string,
  repoName: string,
  configRelPath: string | undefined,
  onProgress?: (message: string) => void,
): Promise<string> {
  const args = ["start", `URL=${target}`, `REPO=${repoName}`];
  if (configRelPath) args.push(`CONFIG=${configRelPath}`);
  if ((process.env.DAPPER_ROUTER || "").toLowerCase() === "true") {
    args.push("ROUTER=true");
  }
  if ((process.env.DAPPER_PIPELINE_TESTING || "").toLowerCase() === "true") {
    args.push("PIPELINE_TESTING=true");
  }

  onProgress?.(`DAST: starting dapper workflow for ${repoName}`);
  const { stdout } = await execFileP("./dapper", args, {
    cwd: workspaceRoot,
    signal: undefined,
    timeout: 30 * 60 * 1000,
    maxBuffer: 32 * 1024 * 1024,
  });

  const match = stdout.match(/Workflow started:\s*([^\s]+)/i);
  if (match?.[1]) return match[1];

  const fallback = stdout.match(/Workflow ID:\s*([^\s]+)/i);
  if (fallback?.[1]) return fallback[1];

  throw new Error(`Unable to parse workflow ID from dapper output: ${stdout}`);
}

async function queryWorkflow(
  workspaceRoot: string,
  workflowId: string,
): Promise<{ status: string; raw: string }> {
  const { stdout } = await execFileP("./dapper", ["query", `ID=${workflowId}`], {
    cwd: workspaceRoot,
    timeout: 5 * 60 * 1000,
    maxBuffer: 8 * 1024 * 1024,
  });

  const status = stdout.match(/Status:\s*([^\n]+)/i)?.[1]?.trim() || "";
  return { status: status.toLowerCase(), raw: stdout };
}

async function waitForWorkflowCompletion(
  workspaceRoot: string,
  workflowId: string,
  onProgress?: (message: string) => void,
): Promise<void> {
  const deadline = Date.now() + 3 * 60 * 60 * 1000;
  while (Date.now() < deadline) {
    const { status, raw } = await queryWorkflow(workspaceRoot, workflowId);
    if (status === "completed") {
      onProgress?.(`DAST: dapper workflow ${workflowId} completed`);
      return;
    }
    if (status === "failed" || status === "error") {
      throw new Error(`Dapper workflow ${workflowId} failed:\n${raw}`);
    }
    if (status) {
      onProgress?.(`DAST: dapper workflow ${workflowId} status=${status}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 30_000));
  }
  throw new Error(`Dapper workflow ${workflowId} timed out`);
}

async function runExporter(
  workspaceRoot: string,
  repoName: string,
  target: string,
  onProgress?: (message: string) => void,
): Promise<{
  findings: RawFinding[];
  developerReportMarkdown: string;
  executiveReportMarkdown: string;
  exportJsonPath: string;
  exportCsvPath: string;
  artifact: unknown;
} | null> {
  const deliverablesDir = path.join(workspaceRoot, "repos", repoName, "deliverables");
  const exportCsvPath = path.join(deliverablesDir, "pepper-findings.csv");
  const exportJsonPath = exportCsvPath.replace(/\.csv$/, "") + "_findings.json";
  const model = process.env.DAPPER_EXPORT_MODEL || DEFAULT_EXPORT_MODEL;
  const maxTurns = String(
    Number.parseInt(process.env.DAPPER_EXPORT_MAX_TURNS || "", 10) ||
      DEFAULT_EXPORT_MAX_TURNS,
  );

  onProgress?.(
    `DAST: exporting findings from ${deliverablesDir} with model=${model}`,
  );

  const env = {
    ...process.env,
  };
  try {
    const { stdout, stderr } = await execFileP(
      "node",
      [
        "scripts/export-findings-csv.js",
        `repos/${repoName}/deliverables`,
        exportCsvPath,
        "--model",
        model,
        "--max-turns",
        maxTurns,
      ],
      {
        cwd: workspaceRoot,
        timeout: 3 * 60 * 60 * 1000,
        maxBuffer: 64 * 1024 * 1024,
        env,
      },
    );

    if (stdout) onProgress?.(`DAST export stdout: ${stdout.slice(0, 500)}`);
    if (stderr) onProgress?.(`DAST export stderr: ${stderr.slice(0, 500)}`);
  } catch (err) {
    onProgress?.(
      `DAST: findings exporter failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
    return null;
  }

  const exportedFindings = readJsonArray(exportJsonPath);
  const developerReportPath = path.join(deliverablesDir, "developer_security_report.md");
  const executiveReportPath = path.join(deliverablesDir, "executive_security_report.md");
  const developerReportMarkdown = fs.existsSync(developerReportPath)
    ? fs.readFileSync(developerReportPath, "utf8")
    : "";
  const executiveReportMarkdown = fs.existsSync(executiveReportPath)
    ? fs.readFileSync(executiveReportPath, "utf8")
    : "";

  const findings = exportedFindings.map((finding) =>
    buildRawFinding(finding, "export", repoName, target),
  );

  const artifact = {
    repoName,
    target,
    deliverablesDir,
    exportJsonPath,
    exportCsvPath,
    developerReportMarkdown,
    executiveReportMarkdown,
    findings: exportedFindings,
  };

  return {
    findings,
    developerReportMarkdown,
    executiveReportMarkdown,
    exportJsonPath,
    exportCsvPath,
    artifact,
  };
}

export async function runLocalDapperWorkspace(
  target: string,
  workDir: string,
  scanId: string | undefined,
  onProgress?: (message: string) => void,
): Promise<DapperWorkspaceResult | null> {
  const workspaceRoot = resolveWorkspaceRoot();
  if (!workspaceRoot) return null;

  try {
    await ensureWorkspaceRoot(workspaceRoot, onProgress);

    const repoName =
      `pepper-${(scanId || Date.now().toString()).replace(/[^a-zA-Z0-9_-]/g, "-")}`;
    await stageTargetRepo(workspaceRoot, repoName, workDir);

    const configRelPath = await prepareConfig(workspaceRoot);
    const workflowId = await startWorkflow(
      workspaceRoot,
      target,
      repoName,
      configRelPath,
      onProgress,
    );
    await waitForWorkflowCompletion(workspaceRoot, workflowId, onProgress);

    const exported = await runExporter(workspaceRoot, repoName, target, onProgress);
    const deliverablesDir = path.join(workspaceRoot, "repos", repoName, "deliverables");
    const comprehensiveReportPath = path.join(
      deliverablesDir,
      "comprehensive_security_assessment_report.md",
    );
    const developerReportMarkdown = exported?.developerReportMarkdown ||
      (fs.existsSync(comprehensiveReportPath)
        ? fs.readFileSync(comprehensiveReportPath, "utf8")
        : "");
    const executiveReportMarkdown = exported?.executiveReportMarkdown ||
      developerReportMarkdown;
    const artifact = exported?.artifact || {
      repoName,
      target,
      deliverablesDir,
      exportJsonPath: exported?.exportJsonPath || "",
      exportCsvPath: exported?.exportCsvPath || "",
      developerReportMarkdown,
      executiveReportMarkdown,
    };

    return {
      workflowId,
      repoName,
      workspaceRoot,
      deliverablesDir,
      findings: exported?.findings || [],
      developerReportMarkdown,
      executiveReportMarkdown,
      exportJsonPath: exported?.exportJsonPath || "",
      exportCsvPath: exported?.exportCsvPath || "",
      artifact,
    };
  } catch (err) {
    onProgress?.(
      `DAST: local dapper orchestration failed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
    return null;
  }
}
