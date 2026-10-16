/**
 * Grounding check for an AI-written report: every finding it cites must exist
 * in the scan. Runs deterministically after the model has written the report.
 *
 *   - [F12]-style refs that the scan does not have are removed; a list item or
 *     table row whose only citations are invalid is dropped entirely (its claim
 *     is about a finding that does not exist);
 *   - raw finding ids are rewritten to their ref when they exist, and treated
 *     like an invalid ref when they do not;
 *   - "N critical findings"-style counts that match neither the scan's total
 *     nor its open count are reported as warnings (not edited: the sentence
 *     may legitimately count a subset).
 */
import type { ReportData, ReportFinding } from "./tools";
import { severityCounts } from "./tools";

export interface GroundingResult {
  markdown: string;
  /** Valid refs cited, in first-cited order. */
  cited: string[];
  /** Citations that did not resolve to a finding of this scan. */
  removed: string[];
  /** Raw ids rewritten to refs. */
  corrected: Array<{ from: string; to: string }>;
  /** Lines dropped because every finding they cited was invalid. */
  droppedLines: number;
  warnings: string[];
}

const REF_TOKEN = /\[(\s*F-?\d{1,6}(?:\s*[,;]\s*F-?\d{1,6})*\s*)\]|\bF-?\d{1,6}\b/g;
/** A cuid-shaped id (Pepper's finding ids): 25 lowercase alnum chars starting with c, with a digit. */
const RAW_ID = /\bc(?=[a-z0-9]*\d)[a-z0-9]{24}\b/g;
const COUNT_CLAIM = /\b(\d{1,6})\s+(critical|high|medium|low|info(?:rmational)?)(?:[-\s]severity)?\s+(?:findings?|issues?|vulnerabilit(?:y|ies)|risks?)\b/gi;

function normRef(token: string): string {
  return token.trim().toUpperCase().replace("-", "");
}

function isListOrRow(line: string): boolean {
  return /^\s*([-*+]|\d{1,3}[.)])\s+/.test(line) || /^\s*\|.*\|\s*$/.test(line);
}

export function groundReport(markdown: string, data: Pick<ReportData, "byRef" | "byId" | "findings">): GroundingResult {
  const cited: string[] = [];
  const citedSet = new Set<string>();
  const removed: string[] = [];
  const corrected: Array<{ from: string; to: string }> = [];
  let droppedLines = 0;
  let inFence = false;

  const out: string[] = [];
  for (const original of markdown.split("\n")) {
    if (/^\s*(```|~~~)/.test(original)) inFence = !inFence;
    if (inFence) {
      out.push(original);
      continue;
    }
    // Raw ids → refs (or markers for removal).
    let line = original.replace(RAW_ID, (id) => {
      const f = data.byId.get(id);
      if (f) {
        corrected.push({ from: id, to: f.ref });
        return `[${f.ref}]`;
      }
      return `[F-INVALID:${id}]`;
    });

    let valid = 0;
    let invalid = 0;
    const lineRemoved: string[] = [];
    line = line.replace(/\[F-INVALID:([a-z0-9]+)\]/g, (_, id: string) => {
      invalid++;
      lineRemoved.push(id);
      return "";
    });
    line = line.replace(REF_TOKEN, (whole, group?: string) => {
      const tokens = group ? group.split(/[,;]/) : [whole];
      const keep: string[] = [];
      for (const t of tokens) {
        const ref = normRef(t);
        if (data.byRef.has(ref)) {
          valid++;
          keep.push(ref);
          if (!citedSet.has(ref)) {
            citedSet.add(ref);
            cited.push(ref);
          }
        } else {
          invalid++;
          lineRemoved.push(ref);
        }
      }
      if (keep.length === 0) return "";
      return group || whole.startsWith("[") ? `[${keep.join(", ")}]` : keep[0];
    });

    if (invalid > 0 && valid === 0 && isListOrRow(original)) {
      droppedLines++;
      removed.push(...lineRemoved);
      continue;
    }
    removed.push(...lineRemoved);
    if (invalid > 0) {
      // Tidy what a removed citation leaves behind.
      line = line
        .replace(/\(\s*(?:see\s*)?\)/gi, "")
        .replace(/[ \t]{2,}/g, " ")
        .replace(/\s+([.,;:])/g, "$1");
    }
    out.push(line);
  }

  // Count claims → warnings.
  const counted = data.findings.filter((f) => f.status !== "FALSE_POSITIVE");
  const totals = severityCounts(counted);
  const open = severityCounts(counted.filter((f) => f.status === "OPEN" || f.status === "IN_PROGRESS"));
  const newer = severityCounts(counted.filter((f) => f.isNew === true));
  const warnings: string[] = [];
  const text = out.join("\n");
  for (const m of text.matchAll(COUNT_CLAIM)) {
    const sev = m[2].toLowerCase().startsWith("info") ? "info" : m[2].toLowerCase();
    const n = Number(m[1]);
    if (n !== totals[sev] && n !== open[sev] && n !== newer[sev]) {
      warnings.push(`"${m[0]}" does not match the scan (${totals[sev]} ${sev} in total, ${open[sev]} open).`);
    }
  }

  return { markdown: text, cited, removed, corrected, droppedLines, warnings: [...new Set(warnings)] };
}

function cell(s: string | null | undefined): string {
  return (s ?? "").replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();
}

/** Appendix listing every cited finding, built from the data (never by the model). */
export function referencedFindingsAppendix(cited: string[], byRef: Map<string, ReportFinding>): string {
  const rows = cited
    .map((r) => byRef.get(r))
    .filter((f): f is ReportFinding => !!f)
    .sort((a, b) => Number(a.ref.slice(1)) - Number(b.ref.slice(1)));
  if (rows.length === 0) return "";
  return [
    "## Referenced findings",
    "",
    "| Ref | Severity | Finding | Location | Status |",
    "| --- | --- | --- | --- | --- |",
    ...rows.map(
      (f) =>
        `| ${f.ref} | ${f.severity} | ${cell(f.title)} | ${cell(f.filePath ? `${f.filePath}${f.startLine ? `:${f.startLine}` : ""}` : "")} | ${f.status} |`,
    ),
  ].join("\n");
}
