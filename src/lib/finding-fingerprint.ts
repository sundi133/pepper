import { createHash } from "node:crypto";
import type { RawFinding } from "@/scanners/types";
import { buildRootCauseKey } from "@/scanners/shared/dedupe";

function normalize(value?: string): string {
  return (value || "").trim().toLowerCase();
}

function normalizeSnippet(snippet?: string): string {
  return normalize(snippet).replace(/\s+/g, " ").slice(0, 400);
}

function stableMetadata(metadata?: Record<string, unknown>): string {
  if (!metadata) return "";
  const ordered = Object.keys(metadata)
    .sort()
    .map((key) => [key, metadata[key]]);
  return JSON.stringify(ordered);
}

/**
 * Build a deterministic fingerprint for noisy LLM-driven findings.
 * The fields selected prioritize semantic identity over exact wording.
 */
export function buildFindingFingerprint(finding: RawFinding): string {
  const rootKey = buildRootCauseKey(finding);
  const payload = [
    rootKey,
    finding.scanner,
    normalize(finding.filePath),
    finding.startLine || 0,
    finding.endLine || 0,
    normalize(finding.ruleId),
    normalize(finding.cweId),
    normalize(finding.cveId),
    normalizeSnippet(finding.snippet),
    stableMetadata(finding.metadata),
  ].join("|");

  return createHash("sha256").update(payload).digest("hex");
}
