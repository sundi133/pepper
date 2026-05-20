import { execFile } from "child_process";
import fs from "fs";
import path from "path";
import { promisify } from "util";
import {
  RawFinding,
  ScanContext,
  ScannerPlugin,
  SeverityLevel,
} from "../types";
import { runLocalDapperWorkspace } from "./orchestrator";
import { redactSensitiveText } from "../shared/evidence-redaction";
import { enrichFinding } from "../shared/finding-normalize";

const execFileP = promisify(execFile);

/**
 * Pepper DAST scanner — delegates dynamic application security testing to
 * an external dapper (https://github.com/sundi133/dapper) instance.
 *
 * Two integration modes are supported:
 *
 *  1. **HTTP API** (preferred for production):
 *     Set `dastEndpoint` to a dapper server URL (e.g. http://dapper:8080)
 *     and `dastApiKey` for auth. Pepper POSTs the target URL and polls
 *     for completion. Dapper must expose:
 *       POST /scans   { target, repo? } -> { id }
 *       GET  /scans/:id  -> { status, findings? }
 *
 *  2. **Docker exec fallback**:
 *     If `dastEndpoint` is unset but a local `dapper` binary or `docker`
 *     command is available, dapper is invoked as a local CLI and the
 *     `audit-logs` directory is parsed.
 *
 * Either mode produces a list of findings normalised to Pepper's RawFinding
 * shape. The scanner is opt-in via per-org settings (`dastEnabled = true`)
 * and per-project DAST target URL.
 */

interface DapperFinding {
  id?: string;
  title: string;
  severity?: string;
  description?: string;
  url?: string;
  cwe?: string;
  evidence?: string;
  confidence?: number;
  request?: string;
  response?: string;
}

interface DapperReport {
  scanId?: string;
  target?: string;
  findings: DapperFinding[];
}

function mapSeverity(s?: string): SeverityLevel {
  switch ((s || "").toUpperCase()) {
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

async function runViaHttp(
  endpoint: string,
  apiKey: string | undefined,
  target: string,
  onProgress?: (m: string) => void,
): Promise<DapperReport | null> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

  const start = await fetch(`${endpoint.replace(/\/+$/, "")}/scans`, {
    method: "POST",
    headers,
    body: JSON.stringify({ target }),
  });
  if (!start.ok) {
    onProgress?.(`DAST: dapper rejected scan request (${start.status})`);
    return null;
  }
  const { id } = (await start.json()) as { id: string };
  onProgress?.(`DAST: dapper scan ${id} queued`);

  // Poll for completion — bounded to ~90 minutes
  const deadline = Date.now() + 90 * 60 * 1000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 15_000));
    const poll = await fetch(
      `${endpoint.replace(/\/+$/, "")}/scans/${encodeURIComponent(id)}`,
      { headers },
    );
    if (!poll.ok) continue;
    const data = (await poll.json()) as {
      status: string;
      findings?: DapperFinding[];
    };
    if (data.status === "COMPLETED" || data.status === "DONE") {
      return { scanId: id, target, findings: data.findings || [] };
    }
    if (data.status === "FAILED" || data.status === "ERROR") {
      onProgress?.(`DAST: dapper scan ${id} failed`);
      return null;
    }
    onProgress?.(`DAST: dapper scan ${id} status=${data.status}`);
  }
  onProgress?.(`DAST: dapper scan ${id} timed out`);
  return null;
}

async function dapperCliAvailable(): Promise<boolean> {
  try {
    await execFileP("dapper", ["--help"], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

async function runViaCli(
  target: string,
  onProgress?: (m: string) => void,
): Promise<DapperReport | null> {
  if (!(await dapperCliAvailable())) {
    onProgress?.("DAST: dapper CLI not available; skipping");
    return null;
  }
  try {
    const { stdout } = await execFileP(
      "dapper",
      ["start", `URL=${target}`, "OUTPUT=json"],
      { timeout: 90 * 60 * 1000, maxBuffer: 128 * 1024 * 1024 },
    );
    const parsed = JSON.parse(stdout) as DapperReport;
    return parsed;
  } catch (err) {
    onProgress?.(
      `DAST: dapper CLI failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return null;
  }
}

function reportToFindings(report: DapperReport): RawFinding[] {
  return report.findings.map((f) => {
    const evidence = redactSensitiveText(f.evidence || "");
    const request = redactSensitiveText(f.request || "");
    const response = redactSensitiveText(f.response || "");
    const base: RawFinding = {
      scanner: "DAST" as const,
      severity: mapSeverity(f.severity),
      title: f.title,
      description: f.description || "",
      filePath: f.url || undefined,
      ruleId: f.id || `DAPPER-${f.title.replace(/\s+/g, "-").slice(0, 48)}`,
      cweId: f.cwe,
      confidence: f.confidence ?? 0.9,
      metadata: {
        dapperScan: report.scanId,
        target: report.target,
        url: f.url,
        evidence,
        category: "DAST",
        weaknessClass: f.cwe,
      },
    };
    return enrichFinding(base, base.metadata as Record<string, unknown>, {
      whatIsWrong: f.title,
      where: f.url || report.target || "target URL",
      whyExploitable: f.description || "Dynamic testing identified exploitable behavior.",
      impact: "See evidence and expected vulnerable behavior in metadata.",
      stepsToReproduce: evidence
        ? [`Review redacted evidence for ${f.url || report.target}`]
        : undefined,
      fix: "Remediate server-side validation, authz, and configuration per finding class.",
      validation: `Re-run DAST against ${f.url || report.target} and confirm issue no longer reproduces`,
    });
  });
}

export const dastScanner: ScannerPlugin = {
  name: "DAST",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    await ctx.waitIfPaused?.();
    const target = ctx.orgSettings.dastTargetUrl;
    if (!target) {
      ctx.onProgress?.(
        "DAST: no target URL configured; skipping (set on project or org)",
      );
      return [];
    }
    const endpoint = ctx.orgSettings.dastEndpoint;
    ctx.onProgress?.(`DAST: starting scan of ${target}`);

    let report: DapperReport | null = null;
    if (endpoint) {
      try {
        report = await runViaHttp(
          endpoint,
          ctx.orgSettings.dastApiKey,
          target,
          ctx.onProgress,
        );
      } catch (err) {
        ctx.onProgress?.(
          `DAST: HTTP scan failed (${err instanceof Error ? err.message : String(err)})`,
        );
        report = null;
      }
    } else {
      const localWorkspace = await runLocalDapperWorkspace(
        target,
        ctx.workDir,
        ctx.scanId,
        ctx.orgSettings.dastConfigYaml,
        ctx.onProgress,
      );
      if (localWorkspace) {
        const reportBundlePath = path.join(
          ctx.workDir,
          "deliverables",
          "dast-report.json",
        );
        fs.mkdirSync(path.dirname(reportBundlePath), { recursive: true });
        fs.writeFileSync(
          reportBundlePath,
          JSON.stringify(
            {
              workflowId: localWorkspace.workflowId,
              repoName: localWorkspace.repoName,
              workspaceRoot: localWorkspace.workspaceRoot,
              target,
              generatedAt: new Date().toISOString(),
              findingsCount: localWorkspace.findings.length,
              developerReportMarkdown: localWorkspace.developerReportMarkdown,
              executiveReportMarkdown: localWorkspace.executiveReportMarkdown,
              exportJsonPath: localWorkspace.exportJsonPath,
              exportCsvPath: localWorkspace.exportCsvPath,
              artifact: localWorkspace.artifact,
            },
            null,
            2,
          ),
        );
        return localWorkspace.findings;
      }
      report = await runViaCli(target, ctx.onProgress);
    }

    if (!report) {
      ctx.onProgress?.(
        `DAST: scan could not complete for ${target} — no findings emitted (configure dastEndpoint or dapper CLI)`,
      );
      return [];
    }

    const findings = reportToFindings(report);
    ctx.onProgress?.(`DAST: ${findings.length} findings from ${target}`);
    return findings;
  },
};
