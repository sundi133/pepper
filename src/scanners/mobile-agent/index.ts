/**
 * Mobile agent "deep scan" scanner (opt-in, additive). When enabled, and when
 * the scan has an uploaded mobile app (.apk/.aab/.ipa), glm-5.3 drives an E2B
 * cloud sandbox to install tools, decompile/extract the app, inspect the
 * first-party code, and report — rather than reviewing pre-decompiled text like
 * the mobile-llm scanner. Its reasoning streams to the live "Model thinking"
 * panel and its findings flow into the normal pipeline.
 *
 * Self-gating (returns [] — a no-op — unless ALL hold), so non-mobile scans and
 * mobile scans with the mode off are completely untouched:
 *   (a) the scan has an uploaded .apk/.aab/.ipa artifact on disk, AND
 *   (b) ENABLE_MOBILE_AGENT_SCAN is set and E2B_API_KEY + OPENROUTER_API_KEY
 *       are present (mobileAgentConfigFromEnv()).
 */
import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanContext, ScannerPlugin, SeverityLevel } from "../types";
import { parseLlmJsonResponse } from "@/lib/llm-gateway";
import { logger } from "@/lib/logger";
import { mobilePlatformOf } from "@/lib/mobile-platform";
import { makeReasoningSink } from "../shared/reasoning-sink";
import { mobileAgentConfigFromEnv } from "./config";
import { runMobileAgent } from "./agent";

const SCANNER_KEY = "mobile-agent";

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

/**
 * The uploaded mobile artifact on disk, as { rel (workDir-relative), name }.
 * Looks in the scan's file list first, then the workDir root (an uploaded
 * compiled artifact can be filtered out of the source file list). Returns null
 * when the scan has no .apk/.aab/.ipa — the scanner then no-ops.
 */
function findMobileArtifact(
  ctx: ScanContext,
): { rel: string; name: string } | null {
  const onDisk = (rel: string): boolean => {
    try {
      return fs.statSync(path.join(ctx.workDir, rel)).isFile();
    } catch {
      return false;
    }
  };

  const fromList = ctx.fileList.find(
    (f) => mobilePlatformOf(f) !== null && onDisk(f),
  );
  if (fromList) return { rel: fromList, name: path.basename(fromList) };

  let entries: string[] = [];
  try {
    entries = fs.readdirSync(ctx.workDir);
  } catch {
    entries = [];
  }
  for (const e of entries) {
    if (mobilePlatformOf(e) !== null && onDisk(e)) return { rel: e, name: e };
  }
  return null;
}

/** Normalizes a MASVS/category string into a stable ruleId slug. */
function ruleIdFor(category: string | undefined): string {
  return `mobile-agent/${(category || "general")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "general"}`;
}

export const mobileAgentScanner: ScannerPlugin = {
  name: SCANNER_KEY,
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const artifact = findMobileArtifact(ctx);
    if (!artifact) return []; // not a mobile upload — no-op

    const cfg = mobileAgentConfigFromEnv();
    if (!cfg) return []; // mode off or keys missing — no-op (never logs on non-mobile scans)

    ctx.onProgress?.(
      `Mobile agent deep scan: ${artifact.name} -> ${cfg.model} (E2B sandbox)`,
    );

    const sink = makeReasoningSink(ctx, SCANNER_KEY);

    let run;
    try {
      run = await runMobileAgent(
        path.join(ctx.workDir, artifact.rel),
        artifact.name,
        cfg,
        { signal: ctx.signal, onReasoning: sink.onReasoning },
      );
    } catch (err) {
      logger.error(
        { err: err instanceof Error ? err.message : String(err) },
        "[mobile-agent] deep scan failed",
      );
      await sink.finalize();
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

    return findings
      .filter((f) => f && f.title)
      .map<RawFinding>((f) => {
        const cwe = f.cweId || f.cwe;
        // Show the evidence against the app it came from, e.g. `app.apk!/com/...`.
        const inner = f.filePath?.replace(/^\/+/, "");
        const filePath = inner ? `${artifact.name}!/${inner}` : artifact.name;
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
            scanner: SCANNER_KEY,
            category: f.category,
            weaknessClass: cwe,
            evidence: f.evidence,
            impact: f.impact,
            remediation: f.remediation,
          },
        };
      });
  },
};
