/**
 * Findings as editor diagnostics (docs/IDE_EXTENSION_SPEC.md §5.3, §5.5).
 * Plain data in LSP shape, so this module needs no LSP library and is unit
 * tested on its own; server.ts hands the objects to the connection.
 */
import type { IdeFinding, PrecommitFinding, Severity } from "./api";
import { reanchor } from "./anchor";

/** LSP DiagnosticSeverity: Error 1, Warning 2, Information 3, Hint 4. */
export function lspSeverity(s: Severity): 1 | 2 | 3 | 4 {
  if (s === "CRITICAL" || s === "HIGH") return 1;
  if (s === "MEDIUM") return 2;
  if (s === "LOW") return 3;
  return 4;
}

const RANK: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
export const atLeast = (s: Severity, min: Severity) => RANK[s] >= RANK[min];

export interface Diagnostic {
  range: { start: { line: number; character: number }; end: { line: number; character: number } };
  severity: 1 | 2 | 3 | 4;
  source: string;
  code?: string;
  codeDescription?: { href: string };
  message: string;
  data: { findingId?: string; onSave?: boolean; cweId?: string | null };
}

const lineRange = (docLines: string[], start: number, end: number): Diagnostic["range"] => {
  const first = docLines[start] ?? "";
  const indent = first.length - first.trimStart().length;
  return {
    start: { line: start, character: Math.min(indent, first.length) },
    end: { line: end, character: (docLines[end] ?? "").length },
  };
};

export function findingDiagnostic(f: IdeFinding, docLines: string[]): Diagnostic {
  const a = reanchor({ startLine: f.startLine, endLine: f.endLine, snippet: f.snippet }, docLines);
  const code = f.cweId || f.cveId || f.ruleId || undefined;
  return {
    range: lineRange(docLines, a.start, a.end),
    severity: lspSeverity(f.severity),
    source: "Pepper",
    ...(code ? { code } : {}),
    ...(f.url ? { codeDescription: { href: f.url } } : {}),
    message: `${f.title.replace(/^\[Zero-Day\]\s*/, "")} [${f.severity}]${a.exact ? "" : " (code may have changed since the scan)"}`,
    data: { findingId: f.id, cweId: f.cweId },
  };
}

export function precommitDiagnostic(f: PrecommitFinding, docLines: string[]): Diagnostic {
  const line = Math.max(0, Math.min(docLines.length - 1, f.line - 1));
  return {
    range: lineRange(docLines, line, line),
    severity: lspSeverity(f.severity),
    source: "Pepper (on-save)",
    ...(f.cweId || f.ruleId ? { code: f.cweId || f.ruleId } : {}),
    message: `${f.title} [${f.severity}]`,
    data: { onSave: true, cweId: f.cweId ?? null },
  };
}

/** On-save results that a scan finding already covers (same line and CWE) are dropped. */
export function dedupeOnSave(onSave: Diagnostic[], scan: Diagnostic[]): Diagnostic[] {
  return onSave.filter((o) => !scan.some((s) => s.range.start.line === o.range.start.line && (!o.data.cweId || s.data.cweId === o.data.cweId)));
}

const norm = (p: string) => p.replace(/\\/g, "/").replace(/^\.?\//, "");

/**
 * Findings for a document at `relPath` (relative to the repository root). The
 * scanned tree may have had a leading folder (an uploaded archive), so a
 * unique suffix match is accepted when nothing matches exactly.
 */
export function findingsForPath(byPath: Map<string, IdeFinding[]>, relPath: string): IdeFinding[] {
  const want = norm(relPath);
  const exact = byPath.get(want);
  if (exact) return exact;
  const keys = [...byPath.keys()].filter((k) => k.endsWith(`/${want}`) || want.endsWith(`/${k}`));
  return keys.length === 1 ? byPath.get(keys[0])! : [];
}

export function indexByPath(findings: IdeFinding[]): Map<string, IdeFinding[]> {
  const m = new Map<string, IdeFinding[]>();
  for (const f of findings) {
    if (!f.filePath || f.filePath.includes("!/")) continue; // inside a compiled artifact: no source to show
    const k = norm(f.filePath);
    m.set(k, [...(m.get(k) ?? []), f]);
  }
  return m;
}

/** Markdown shown on hover and copied by "Copy finding". */
export function findingMarkdown(f: IdeFinding): string {
  const lines = [
    `**${f.title.replace(/^\[Zero-Day\]\s*/, "")}**`,
    "",
    `${f.severity} · ${f.scanner}${f.cweId ? ` · ${f.cweId}` : ""}${f.cveId ? ` · ${f.cveId}` : ""}${f.validation ? ` · ${f.validation}` : ""}`,
  ];
  if (f.description) lines.push("", f.description.slice(0, 2000));
  if (f.attackPath) lines.push("", `**Attack path:** ${f.attackPath.slice(0, 1000)}`);
  if (f.remediation) lines.push("", `**Fix:** ${f.remediation.slice(0, 1500)}`);
  if (f.filePath) lines.push("", `\`${f.filePath}${f.startLine ? `:${f.startLine}` : ""}\``);
  if (f.url) lines.push("", `[Open in Pepper](${f.url})`);
  return lines.join("\n");
}

export interface Counts { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; INFO: number }

export function countBySeverity(findings: IdeFinding[]): Counts {
  const c: Counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}
