/**
 * Agent "deep scan" scanner. For an uploaded compiled/binary artifact
 * (.apk/.aab/.ipa/.dex/.jar/.war/.ear/.dll/.exe) on a configured instance, it
 * is the SOLE reviewer: glm-5.3 drives an E2B cloud sandbox to install the
 * right decompiler, decompile/extract the artifact, inspect the first-party
 * code, and report. Its reasoning streams to the live "Model thinking" panel
 * and its findings flow into the normal pipeline.
 *
 * Self-gating (returns [] — a no-op — unless ALL hold), so source/repo scans
 * and unconfigured instances are untouched:
 *   (a) the scan source is a single uploaded binary artifact (ctx.uploadedArtifact),
 *   (b) that artifact is an agent-handled type (isAgentArtifact), AND
 *   (c) ENABLE_AGENT_SCAN is set with E2B_API_KEY + OPENROUTER_API_KEY.
 * The processor skips the local decompile + rule scanners only when the agent
 * is configured for the upload; otherwise those run and the agent no-ops here.
 */
import * as path from "path";
import { RawFinding, ScanContext, ScannerPlugin, SeverityLevel } from "../types";
import { parseLlmJsonResponse } from "@/lib/llm-gateway";
import { logger } from "@/lib/logger";
import { makeReasoningSink } from "../shared/reasoning-sink";
import { agentScanConfigFromEnv } from "./config";
import { isAgentArtifact } from "./artifact";
import { runAgentScan } from "./agent";

export const AGENT_SCANNER_KEY = "agent-scan";

interface AgentFinding {
  title?: string;
  severity?: string;
  confidence?: number;
  category?: string;
  cweId?: string;
  cwe?: string;
  filePath?: string;
  evidence?: string;
  impact?: string;
  remediation?: string;
  description?: string;
}

function normSeverity(s: string | undefined): SeverityLevel {
  const u = (s || "").toUpperCase();
  return (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).includes(
    u as SeverityLevel,
  )
    ? (u as SeverityLevel)
    : "MEDIUM";
}

/** Normalizes a category string into a stable ruleId slug. */
function ruleIdFor(category: string | undefined): string {
  return `agent/${(category || "general")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "general"}`;
}

export const mobileAgentScanner: ScannerPlugin = {
  name: AGENT_SCANNER_KEY,
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const uploaded = ctx.uploadedArtifact;
    // Only a single uploaded binary artifact — never a file found inside a
    // source archive or repo checkout, so source/repo scans are untouched.
    if (!uploaded || !isAgentArtifact(uploaded)) return [];

    const cfg = agentScanConfigFromEnv();
    if (!cfg) return []; // mode off or keys missing — the normal pipeline handles the binary

    const name = path.basename(uploaded);
    ctx.onProgress?.(`Agent deep scan: ${name} -> ${cfg.model} (E2B sandbox)`);
    await ctx.onAgentStatus?.({ status: "RUNNING", note: "starting the E2B sandbox" });

    const sink = makeReasoningSink(ctx, AGENT_SCANNER_KEY);

    let run;
    try {
      run = await runAgentScan(path.join(ctx.workDir, uploaded), name, cfg, {
        signal: ctx.signal,
        onReasoning: sink.onReasoning,
        onSandbox: (sandboxId) => {
          void ctx.onAgentStatus?.({
            status: "RUNNING",
            sandboxId,
            note: sandboxId ? `running in sandbox ${sandboxId}` : "running in sandbox",
          });
        },
      });
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      logger.error({ err: reason }, "[agent-scan] deep scan failed");
      await sink.finalize();
      await ctx.onAgentStatus?.({
        status: "DONE",
        outcome: "failed",
        note: reason.slice(0, 500),
      });
      return [];
    }

    // Persist the full reasoning + command trace (processor stores it as the
    // AI_REASONING artifact). Best-effort: never fail the scan over storage.
    await sink.finalize();

    const parsed = parseLlmJsonResponse<{ findings: AgentFinding[] }>(
      run.content,
      { findings: [] },
    );
    const findings = Array.isArray(parsed.findings) ? parsed.findings : [];

    const mapped = findings
      .filter((f) => f && f.title)
      .map<RawFinding>((f) => {
        const cwe = f.cweId || f.cwe;
        // Show the evidence against the artifact it came from, e.g. `app.jar!/com/...`.
        const inner = f.filePath?.replace(/^\/+/, "");
        const filePath = inner ? `${name}!/${inner}` : name;
        return {
          scanner: "SAST_LLM",
          severity: normSeverity(f.severity),
          title: f.title!.slice(0, 200),
          description: f.description || f.impact || "",
          filePath,
          snippet: f.evidence,
          ruleId: ruleIdFor(f.category),
          cweId: cwe,
          confidence:
            typeof f.confidence === "number"
              ? Math.max(0, Math.min(1, f.confidence))
              : undefined,
          metadata: {
            scanner: AGENT_SCANNER_KEY,
            category: f.category,
            weaknessClass: cwe,
            evidence: f.evidence,
            impact: f.impact,
            remediation: f.remediation,
          },
        };
      });

    await ctx.onAgentStatus?.({
      status: "DONE",
      outcome: run.finished ? "completed" : "incomplete",
      findingsCount: mapped.length,
      note: run.finished
        ? undefined
        : "stopped at the step/time limit; reported what it found so far",
    });

    return mapped;
  },
};
