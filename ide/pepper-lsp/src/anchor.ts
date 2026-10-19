/**
 * Re-anchoring (docs/IDE_EXTENSION_SPEC.md §5.4): a finding's line refers to
 * the scanned commit; find where its code is in the document now.
 */

export interface AnchorInput {
  startLine: number | null; // 1-based, from the scan
  endLine: number | null;
  snippet: string | null;
}

export interface Anchored {
  /** 0-based line range in the current document. */
  start: number;
  end: number;
  /** False when the code could not be found again; the reported line is used. */
  exact: boolean;
}

const SEARCH_WINDOW = 200;
const squash = (s: string) => s.replace(/\s+/g, "");
const trivial = (s: string) => squash(s).length < 4 || /^[\s{}()[\];,.:'"`<>/*#-]*$/.test(s);

interface SnippetLine { text: string; line: number | null }

/** Snippet lines with any "12: " prefixes removed, and their numbers when present. */
export function snippetLines(snippet: string): SnippetLine[] {
  return snippet.split("\n").map((raw) => {
    const m = /^\s*(\d+):\s?(.*)$/.exec(raw);
    return m ? { text: m[2], line: Number(m[1]) } : { text: raw, line: null };
  });
}

/** The snippet line to look for: the one at the reported line, else the longest. */
export function anchorLine(snippet: string, startLine: number | null): { text: string; offset: number } | null {
  const lines = snippetLines(snippet);
  const usable = lines.filter((l) => !trivial(l.text));
  if (!usable.length) return null;
  const numbered = startLine != null ? usable.find((l) => l.line === startLine) : undefined;
  if (numbered) return { text: numbered.text, offset: 0 };
  const longest = usable.reduce((a, b) => (squash(b.text).length > squash(a.text).length ? b : a));
  // Distance from the reported start line, when the snippet carries numbers.
  const offset = longest.line != null && startLine != null ? longest.line - startLine : 0;
  return { text: longest.text, offset };
}

export function reanchor(f: AnchorInput, docLines: string[]): Anchored {
  const n = docLines.length;
  const clamp = (x: number) => Math.max(0, Math.min(Math.max(0, n - 1), x));
  const reportedStart = clamp((f.startLine ?? 1) - 1);
  const span = Math.max(0, (f.endLine ?? f.startLine ?? 1) - (f.startLine ?? 1));
  const fallback: Anchored = { start: reportedStart, end: clamp(reportedStart + span), exact: !f.snippet };
  if (!f.snippet) return fallback;

  const anchor = anchorLine(f.snippet, f.startLine);
  if (!anchor) return { ...fallback, exact: true };
  const want = squash(anchor.text);
  const expected = reportedStart + anchor.offset;

  let best = -1;
  let bestDist = Infinity;
  let tie = false;
  const from = Math.max(0, expected - SEARCH_WINDOW);
  const to = Math.min(n - 1, expected + SEARCH_WINDOW);
  for (let i = from; i <= to; i++) {
    if (squash(docLines[i]) !== want && !(want.length >= 12 && squash(docLines[i]).includes(want))) continue;
    const d = Math.abs(i - expected);
    if (d < bestDist) {
      best = i;
      bestDist = d;
      tie = false;
    } else if (d === bestDist) {
      tie = true;
    }
  }
  if (best < 0 || tie) return { ...fallback, exact: false };
  const start = clamp(best - anchor.offset);
  return { start, end: clamp(start + span), exact: true };
}
