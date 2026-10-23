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
import { agentScanConfig } from "./config";
import { isAgentArtifact } from "./artifact";
import { runAgentScan, type ReportedFinding } from "./agent";

export const AGENT_SCANNER_KEY = "agent-scan";

/** The final-JSON finding shape (safety-net for anything not streamed via report_finding). */
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

/** Normalized shape both report_finding and the final JSON map through, so they dedupe cleanly. */
interface CommonFinding {
  title: string;
  severity?: string;
  confidence?: number;
  category?: string;
  cweId?: string;
  innerPath?: string;
  startLine?: number;
  description?: string;
  evidence?: string;
  impact?: string;
  remediation?: string;
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

/** report_finding's string confidence → a 0..1 number. */
function confidenceOf(c: string | undefined): number | undefined {
  switch ((c || "").toLowerCase()) {
    case "high":
      return 0.9;
    case "medium":
      return 0.6;
    case "low":
      return 0.3;
    default:
      return undefined;
  }
}

/** Builds a RawFinding scoped to the uploaded artifact (e.g. `app.apk!/com/...`). */
function toRawFinding(artifactName: string, c: CommonFinding): RawFinding {
  const inner = c.innerPath?.replace(/^\/+/, "");
  const filePath = inner ? `${artifactName}!/${inner}` : artifactName;
  return {
    scanner: "SAST_LLM",
    severity: normSeverity(c.severity),
    title: c.title.slice(0, 200),
    description: c.description || c.impact || "",
    filePath,
    startLine: typeof c.startLine === "number" && c.startLine > 0 ? c.startLine : undefined,
    snippet: c.evidence,
    ruleId: ruleIdFor(c.category),
    cweId: c.cweId,
    confidence:
      typeof c.confidence === "number" ? Math.max(0, Math.min(1, c.confidence)) : undefined,
    metadata: {
      scanner: AGENT_SCANNER_KEY,
      category: c.category,
      weaknessClass: c.cweId,
      evidence: c.evidence,
      impact: c.impact,
      remediation: c.remediation,
    },
  };
}

/** report_finding (streamed) → CommonFinding. */
function reportedToCommon(f: ReportedFinding): CommonFinding {
  const parts = [
    f.vulnerability || "",
    f.attack ? `\n\nAttack: ${f.attack}` : "",
    f.fix ? `\n\nFix: ${f.fix}` : "",
  ];
  return {
    title: (f.title || "").slice(0, 200),
    severity: f.severity,
    confidence: confidenceOf(f.confidence),
    cweId: f.cwe || undefined,
    innerPath: f.file,
    startLine: typeof f.line === "number" ? f.line : undefined,
    description: parts.join("").trim(),
    evidence: f.vulnerability,
    impact: f.attack,
    remediation: f.fix,
  };
}

/** Final-JSON finding → CommonFinding. */
function finalToCommon(f: AgentFinding): CommonFinding {
  return {
    title: (f.title || "").slice(0, 200),
    severity: f.severity,
    confidence: f.confidence,
    category: f.category,
    cweId: f.cweId || f.cwe,
    innerPath: f.filePath,
    description: f.description || f.impact,
    evidence: f.evidence,
    impact: f.impact,
    remediation: f.remediation,
  };
}

/** A loose identity key for counting distinct findings across the two paths. */
function findingKey(f: RawFinding): string {
  return `${(f.filePath || "").toLowerCase()}|${f.title.toLowerCase()}`;
}

export const mobileAgentScanner: ScannerPlugin = {
  name: AGENT_SCANNER_KEY,
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const uploaded = ctx.uploadedArtifact;
    // Only a single uploaded binary artifact — never a file found inside a
    // source archive or repo checkout, so source/repo scans are untouched.
    if (!uploaded || !isAgentArtifact(uploaded)) return [];

    // Prefer the org's own OpenRouter key (LLM Config); env is only a fallback.
    const cfg = agentScanConfig(ctx.orgSettings);
    if (!cfg) return []; // mode off or keys missing — the normal pipeline handles the binary

    const name = path.basename(uploaded);
    ctx.onProgress?.(
      `Agent deep scan: ${name} -> ${cfg.model} (E2B sandbox, ${cfg.keySource} OpenRouter key)`,
    );
    await ctx.onAgentStatus?.({ status: "RUNNING", note: "starting the E2B sandbox" });

    const sink = makeReasoningSink(ctx, AGENT_SCANNER_KEY);

    // Findings the model streams via report_finding, inserted into the Findings
    // tab the moment they arrive (same incremental path as SAST_LLM). The
    // final-JSON array is parsed below as a safety net; the shared
    // FindingDeduplicator drops anything already streamed, so nothing double-counts.
    const liveFindings: RawFinding[] = [];

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
        onFinding: async (reported) => {
          if (!reported?.title) return;
          const rf = toRawFinding(name, reportedToCommon(reported));
          liveFindings.push(rf);
          try {
            // Incremental insert → dedup → persist, so it shows live.
            await ctx.onBatchFindings?.(AGENT_SCANNER_KEY, [rf]);
          } catch {
            /* best-effort live insert; it is also returned at the end as a safety net */
          }
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

    // Safety net: any finding in the final JSON that the model did not stream
    // via report_finding. The deduplicator drops ones already streamed.
    const parsed = parseLlmJsonResponse<{ findings: AgentFinding[] }>(
      run.content,
      { findings: [] },
    );
    const finalFindings = (Array.isArray(parsed.findings) ? parsed.findings : [])
      .filter((f) => f && f.title)
      .map((f) => toRawFinding(name, finalToCommon(f)));

    // Return streamed + final; FindingDeduplicator (shared across onBatchFindings
    // and onScannerComplete) keeps each root cause once.
    const all = [...liveFindings, ...finalFindings];
    const distinct = new Set(all.map(findingKey)).size;

    await ctx.onAgentStatus?.({
      status: "DONE",
      outcome: run.finished ? "completed" : "incomplete",
      // Raw pre-dedup count the agent produced; the banner shows the deduped,
      // persisted count (scannerProgress["agent-scan"].findingsCount) so it
      // matches the Findings tab, and uses this only for a "N reported" note.
      reported: distinct,
      note: run.finished
        ? undefined
        : "stopped at the step/time limit; reported what it found so far",
    });

    return all;
  },
};
