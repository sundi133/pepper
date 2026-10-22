/**
 * Mobile review scanner. Runs AFTER the compiled-code step has decompiled an
 * uploaded .apk (jadx) — it reviews that decompiled source plus the decoded
 * AndroidManifest for mobile-specific weaknesses (exported components, WebView
 * bridges, weak crypto, cleartext, embedded secrets, MASVS) that the generic
 * source scanners miss. Self-gating: it does nothing unless an AndroidManifest
 * is present, so non-mobile scans are untouched. iOS (.ipa) plugs in here later
 * once extraction is wired up.
 */
import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanContext, ScannerPlugin, SeverityLevel } from "../types";
import { parseLlmJsonResponse } from "@/lib/llm-gateway";
import { logger } from "@/lib/logger";
import {
  mobileReviewConfigFromEnv,
  reviewMobileBundle,
  type MobileReviewResult,
} from "./glm-review";

// Context budget for the review bundle. GLM-5.3 has a large window; this keeps
// cost and latency sane for a scanner while fitting the manifest + key source.
const MAX_TOTAL_CHARS = 300_000;
const MAX_FILE_CHARS = 24_000;

interface MobileFinding {
  title?: string;
  severity?: string;
  confidence?: number;
  category?: string;
  cwe?: string;
  filePath?: string;
  line?: number;
  component?: string;
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

function filePriority(rel: string): number {
  const b = rel.toLowerCase();
  if (b.endsWith("androidmanifest.xml")) return 0;
  if (b.includes("network_security") || b.endsWith("strings.xml")) return 1;
  if (b.includes("/res/") && b.endsWith(".xml")) return 2;
  if (b.endsWith(".java") || b.endsWith(".kt")) return 3;
  return 4;
}

/**
 * The mobile anchor file: AndroidManifest.xml (decompiled .apk) or Info.plist
 * (extracted .ipa). Its presence is what tells this scanner the scan is mobile;
 * absent it, the scanner no-ops so non-mobile scans are untouched.
 */
function findMobileAnchor(fileList: string[]): string | null {
  return (
    fileList.find((f) => {
      const b = f.toLowerCase();
      return (
        b.endsWith("androidmanifest.xml") ||
        b === "info.plist" ||
        b.endsWith("/info.plist")
      );
    }) ?? null
  );
}

function buildBundle(ctx: ScanContext): { text: string; included: number } {
  const relevant = ctx.fileList
    .filter((f) => {
      const b = f.toLowerCase();
      return (
        b.endsWith(".java") ||
        b.endsWith(".kt") ||
        b.endsWith(".xml") ||
        b.endsWith(".plist")
      );
    })
    .sort((a, b) => filePriority(a) - filePriority(b) || a.localeCompare(b));

  const parts: string[] = [];
  let total = 0;
  let included = 0;
  for (const rel of relevant) {
    if (total >= MAX_TOTAL_CHARS) break;
    let content: string;
    try {
      content = fs.readFileSync(path.join(ctx.workDir, rel), "utf8");
    } catch {
      continue;
    }
    if (content.length > MAX_FILE_CHARS) {
      content = content.slice(0, MAX_FILE_CHARS) + "\n… (truncated)\n";
    }
    const chunk = `\n===== FILE: ${rel} =====\n${content}`;
    if (total + chunk.length > MAX_TOTAL_CHARS) continue;
    parts.push(chunk);
    total += chunk.length;
    included++;
  }
  return { text: parts.join(""), included };
}

export const mobileLlmScanner: ScannerPlugin = {
  name: "mobile-llm",
  async scan(ctx: ScanContext): Promise<RawFinding[]> {
    const anchor = findMobileAnchor(ctx.fileList);
    if (!anchor) return []; // not a mobile scan (no manifest / Info.plist) — no-op

    const cfg = mobileReviewConfigFromEnv();
    if (!cfg) {
      logger.warn(
        "[mobile-llm] mobile app detected but OPENROUTER_API_KEY not set; skipping mobile review",
      );
      return [];
    }

    const { text, included } = buildBundle(ctx);
    if (!text) return [];
    ctx.onProgress?.(`Mobile review: ${included} files -> ${cfg.model}`);

    // Stream reasoning to the developer progress feed, buffered so we don't
    // write per token; the full trace is persisted below via ctx.onReasoning.
    let buf = "";
    const flush = () => {
      if (buf) {
        ctx.onProgress?.(`[mobile-llm reasoning] ${buf}`);
        buf = "";
      }
    };

    let result: MobileReviewResult;
    try {
      result = await reviewMobileBundle(text, cfg, {
        signal: ctx.signal,
        onReasoning: (d) => {
          buf += d;
          if (buf.length >= 400) flush();
        },
      });
      flush();
    } catch (err) {
      logger.error(
        { err: err instanceof Error ? err.message : String(err) },
        "[mobile-llm] review request failed",
      );
      return [];
    }

    // Persist the full reasoning trace for developers (processor stores it as a
    // ScanArtifact). Best-effort: never let storage failures fail the scan.
    if (result.reasoning) {
      try {
        await ctx.onReasoning?.("mobile-llm", result.reasoning);
      } catch {
        /* storage is best-effort */
      }
    }

    const parsed = parseLlmJsonResponse<{ findings: MobileFinding[] }>(
      result.content,
      { findings: [] },
    );
    const findings = Array.isArray(parsed.findings) ? parsed.findings : [];

    return findings
      .filter((f) => f && f.title)
      .map<RawFinding>((f) => ({
        scanner: "SAST_LLM",
        severity: normSeverity(f.severity),
        title: f.title!.slice(0, 200),
        description: f.description || "",
        filePath: f.filePath || anchor,
        startLine: typeof f.line === "number" && f.line > 0 ? f.line : undefined,
        snippet: f.evidence,
        ruleId: `mobile/${(f.category || "general").toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
        cweId: f.cwe,
        confidence:
          typeof f.confidence === "number"
            ? Math.max(0, Math.min(1, f.confidence))
            : undefined,
        metadata: {
          scanner: "mobile-llm",
          category: f.category,
          weaknessClass: f.cwe,
          affectedComponent: f.component,
          evidence: f.evidence,
          impact: f.impact,
          remediation: f.remediation,
        },
      }));
  },
};
