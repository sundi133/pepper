/**
 * Pure helpers for building inline PR review comments. No I/O — separated
 * so the patch-parsing and marker logic can be unit tested.
 */

import { createHash } from "node:crypto";

export interface InlineFinding {
  severity: string;
  title: string;
  description: string;
  filePath: string | null;
  startLine: number | null;
  ruleId: string | null;
  cweId: string | null;
}

const FINDING_MARKER_PREFIX = "<!-- pepper-finding:";
const FINDING_MARKER_SUFFIX = " -->";

export function buildFindingMarker(finding: InlineFinding): string {
  const payload = [
    (finding.filePath || "").toLowerCase().trim(),
    finding.startLine ?? 0,
    (finding.ruleId || "").toLowerCase().trim(),
    (finding.cweId || "").toLowerCase().trim(),
    (finding.title || "").toLowerCase().trim(),
  ].join("|");
  const hash = createHash("sha256").update(payload).digest("hex").slice(0, 16);
  return `${FINDING_MARKER_PREFIX}${hash}${FINDING_MARKER_SUFFIX}`;
}

export function extractFindingMarkers(body: string | null | undefined): string[] {
  if (!body) return [];
  const re = /<!-- pepper-finding:[a-f0-9]+ -->/g;
  return body.match(re) ?? [];
}

/**
 * Given a GitHub PR file `patch` blob, return the set of new-file line
 * numbers (RIGHT side) that can receive an inline review comment — those
 * that appear in the patch as either context (` `) or added (`+`).
 */
export function parsePatchAddedLines(patch: string | null | undefined): Set<number> {
  const out = new Set<number>();
  if (!patch) return out;

  const lines = patch.split("\n");
  let rightLine = 0;
  let inHunk = false;

  for (const raw of lines) {
    if (raw.startsWith("@@")) {
      const m = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (m) {
        rightLine = parseInt(m[1], 10);
        inHunk = true;
      } else {
        inHunk = false;
      }
      continue;
    }
    if (!inHunk) continue;
    if (raw.startsWith("\\")) continue;
    const sigil = raw[0];
    if (sigil === "+" ) {
      out.add(rightLine);
      rightLine++;
    } else if (sigil === "-") {
      // removed line — does not consume a RIGHT-side line number
    } else {
      // context (' ') or empty line in patch — exists on both sides
      out.add(rightLine);
      rightLine++;
    }
  }
  return out;
}

function severityHint(severity: string): string {
  const s = severity.toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return "**warning**";
  if (s === "MEDIUM") return "**suggestion**";
  return "**nitpick**";
}

export interface InlineCommentBuildOptions {
  reviewUrl: string | null;
}

export function buildInlineCommentBody(
  finding: InlineFinding,
  opts: InlineCommentBuildOptions,
): string {
  const marker = buildFindingMarker(finding);
  const lines: string[] = [];
  lines.push(marker);
  lines.push(
    `${severityHint(finding.severity)} _Pepper · ${finding.severity}${finding.ruleId ? ` · ${finding.ruleId}` : ""}_`,
  );
  lines.push("");
  lines.push(`**${escapeMd(finding.title)}**`);
  if (finding.description) {
    lines.push("");
    lines.push(truncate(finding.description, 800));
  }
  const refs: string[] = [];
  if (finding.cweId) refs.push(finding.cweId);
  if (refs.length) {
    lines.push("");
    lines.push(`_References: ${refs.join(", ")}_`);
  }
  if (opts.reviewUrl) {
    lines.push("");
    lines.push(`[View full finding in Pepper](${opts.reviewUrl})`);
  }
  return lines.join("\n");
}

function escapeMd(s: string): string {
  return s.replace(/[<>]/g, (c) => (c === "<" ? "&lt;" : "&gt;"));
}

function truncate(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max - 1).trimEnd() + "…";
}

export interface ReviewComment {
  path: string;
  line: number;
  side: "RIGHT";
  body: string;
}

/**
 * Filter findings down to those that have a file path, a start line, fall
 * inside a changed-file hunk on the new side, and have not already been
 * commented on this PR.
 */
export function selectFindingsForInline(
  findings: InlineFinding[],
  changedFileLines: Map<string, Set<number>>,
  existingMarkers: Set<string>,
  maxComments: number,
): ReviewComment[] {
  const out: ReviewComment[] = [];
  for (const f of findings) {
    if (!f.filePath || f.startLine == null || f.startLine <= 0) continue;
    const hunkLines = changedFileLines.get(f.filePath);
    if (!hunkLines) continue;
    if (!hunkLines.has(f.startLine)) continue;
    const marker = buildFindingMarker(f);
    if (existingMarkers.has(marker)) continue;
    out.push({
      path: f.filePath,
      line: f.startLine,
      side: "RIGHT",
      body: "", // body filled by caller using buildInlineCommentBody
    });
    if (out.length >= maxComments) break;
  }
  return out;
}
