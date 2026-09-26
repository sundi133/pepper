/**
 * Pure helpers for the remediation agent: apply the model's search/replace
 * edits to a file and render a unified diff for the UI and PR body.
 *
 * The model proposes edits as exact `search` → `replace` blocks instead of
 * rewriting whole files, so large files are never truncated and every change
 * is reviewable as a small diff.
 */

export interface SearchReplaceEdit {
  path: string;
  /** Exact text to replace. Empty = create `path` as a new file. */
  search: string;
  replace: string;
}

export type ApplyEditsResult =
  | { ok: true; content: string }
  | { ok: false; error: string };

function countOccurrences(haystack: string, needle: string): number {
  if (!needle) return 0;
  let count = 0;
  let from = 0;
  while (true) {
    const idx = haystack.indexOf(needle, from);
    if (idx === -1) return count;
    count++;
    from = idx + needle.length;
  }
}

/**
 * Locate `search` in `content` tolerating trailing-whitespace and CRLF
 * differences per line. Returns the [start, end) character range of the
 * matched original text, or null when not found / ambiguous.
 */
function fuzzyLineRange(
  content: string,
  search: string,
): { start: number; end: number } | { ambiguous: true } | null {
  const norm = (s: string) => s.replace(/\r$/, "").replace(/[ \t]+$/, "");
  const lines = content.split("\n");
  const searchLines = search.replace(/\n$/, "").split("\n").map(norm);
  if (searchLines.length === 0) return null;

  const offsets: number[] = [];
  let acc = 0;
  for (const line of lines) {
    offsets.push(acc);
    acc += line.length + 1;
  }

  const matches: number[] = [];
  for (let i = 0; i + searchLines.length <= lines.length; i++) {
    let hit = true;
    for (let j = 0; j < searchLines.length; j++) {
      if (norm(lines[i + j]) !== searchLines[j]) {
        hit = false;
        break;
      }
    }
    if (hit) matches.push(i);
    if (matches.length > 1) return { ambiguous: true };
  }
  if (matches.length !== 1) return null;
  const first = matches[0];
  const last = first + searchLines.length - 1;
  const start = offsets[first];
  // End of the last matched line, excluding its line terminator (\n or \r\n)
  // so the replacement keeps it.
  const end = offsets[last] + lines[last].replace(/\r$/, "").length;
  return { start, end };
}

/** Apply edits targeting a single file, in order. */
export function applyEditsToContent(
  original: string | null,
  edits: Array<Pick<SearchReplaceEdit, "search" | "replace">>,
  path: string,
): ApplyEditsResult {
  let content = original;
  for (const [i, edit] of edits.entries()) {
    const label = `edit ${i + 1} for ${path}`;
    if (content === null) {
      if (edit.search !== "") {
        return { ok: false, error: `${label}: file does not exist` };
      }
      content = edit.replace;
      continue;
    }
    if (edit.search === "") {
      return {
        ok: false,
        error: `${label}: empty search block, but the file already exists — quote the exact lines to replace`,
      };
    }
    const exact = countOccurrences(content, edit.search);
    if (exact === 1) {
      content = content.replace(edit.search, () => edit.replace);
      continue;
    }
    if (exact > 1) {
      return {
        ok: false,
        error: `${label}: search block matches ${exact} places — include more surrounding lines so it is unique`,
      };
    }
    const fuzzy = fuzzyLineRange(content, edit.search);
    if (fuzzy && "ambiguous" in fuzzy) {
      return {
        ok: false,
        error: `${label}: search block matches several places — include more surrounding lines so it is unique`,
      };
    }
    if (!fuzzy) {
      return {
        ok: false,
        error: `${label}: search block not found — copy the lines verbatim from the file`,
      };
    }
    // Match the file's line endings so a CRLF file stays CRLF.
    const eol = content.includes("\r\n") ? "\r\n" : "\n";
    const replacement = edit.replace.replace(/\n$/, "").replace(/\r?\n/g, eol);
    content =
      content.slice(0, fuzzy.start) + replacement + content.slice(fuzzy.end);
  }
  return { ok: true, content: content ?? "" };
}

// ─── Unified diff ────────────────────────────────────────────────────

type Op = { kind: " " | "-" | "+"; line: string };

/** Max cells for the LCS table; larger regions fall back to delete+add. */
const MAX_LCS_CELLS = 4_000_000;

function diffLines(a: string[], b: string[]): Op[] {
  let prefix = 0;
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) {
    prefix++;
  }
  let suffix = 0;
  while (
    suffix < a.length - prefix &&
    suffix < b.length - prefix &&
    a[a.length - 1 - suffix] === b[b.length - 1 - suffix]
  ) {
    suffix++;
  }
  const midA = a.slice(prefix, a.length - suffix);
  const midB = b.slice(prefix, b.length - suffix);

  const ops: Op[] = a.slice(0, prefix).map((line) => ({ kind: " ", line }));

  if (midA.length * midB.length > MAX_LCS_CELLS) {
    for (const line of midA) ops.push({ kind: "-", line });
    for (const line of midB) ops.push({ kind: "+", line });
  } else {
    const n = midA.length;
    const m = midB.length;
    const dp: Uint32Array[] = Array.from(
      { length: n + 1 },
      () => new Uint32Array(m + 1),
    );
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        dp[i][j] =
          midA[i] === midB[j]
            ? dp[i + 1][j + 1] + 1
            : Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
    let i = 0;
    let j = 0;
    while (i < n && j < m) {
      if (midA[i] === midB[j]) {
        ops.push({ kind: " ", line: midA[i] });
        i++;
        j++;
      } else if (dp[i + 1][j] >= dp[i][j + 1]) {
        ops.push({ kind: "-", line: midA[i++] });
      } else {
        ops.push({ kind: "+", line: midB[j++] });
      }
    }
    while (i < n) ops.push({ kind: "-", line: midA[i++] });
    while (j < m) ops.push({ kind: "+", line: midB[j++] });
  }

  for (const line of a.slice(a.length - suffix)) ops.push({ kind: " ", line });
  return ops;
}

function splitLines(s: string): string[] {
  if (s === "") return [];
  const lines = s.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/**
 * Render a git-style unified diff for one file. `before === null` means the
 * file is new. Returns "" when nothing changed.
 */
export function unifiedDiff(
  path: string,
  before: string | null,
  after: string,
  context = 3,
): string {
  if (before === after) return "";
  const a = splitLines(before ?? "");
  const b = splitLines(after);
  const ops = diffLines(a, b);

  const changeIdx: number[] = [];
  ops.forEach((op, idx) => {
    if (op.kind !== " ") changeIdx.push(idx);
  });
  if (changeIdx.length === 0) return "";

  // Group changes into hunks separated by more than 2*context unchanged lines.
  const hunks: Array<[number, number]> = [];
  let start = Math.max(0, changeIdx[0] - context);
  let end = Math.min(ops.length, changeIdx[0] + context + 1);
  for (const idx of changeIdx.slice(1)) {
    if (idx - context <= end) {
      end = Math.min(ops.length, idx + context + 1);
    } else {
      hunks.push([start, end]);
      start = Math.max(0, idx - context);
      end = Math.min(ops.length, idx + context + 1);
    }
  }
  hunks.push([start, end]);

  const out: string[] = [
    before === null ? "--- /dev/null" : `--- a/${path}`,
    `+++ b/${path}`,
  ];
  for (const [hs, he] of hunks) {
    let aLine = 1;
    let bLine = 1;
    for (let k = 0; k < hs; k++) {
      if (ops[k].kind !== "+") aLine++;
      if (ops[k].kind !== "-") bLine++;
    }
    let aCount = 0;
    let bCount = 0;
    const body: string[] = [];
    for (let k = hs; k < he; k++) {
      const op = ops[k];
      if (op.kind !== "+") aCount++;
      if (op.kind !== "-") bCount++;
      body.push(`${op.kind}${op.line}`);
    }
    const aStart = aCount === 0 ? aLine - 1 : aLine;
    const bStart = bCount === 0 ? bLine - 1 : bLine;
    out.push(`@@ -${aStart},${aCount} +${bStart},${bCount} @@`);
    out.push(...body);
  }
  return out.join("\n");
}

/** Count added/removed lines in a unified diff. */
export function diffStats(diff: string): { added: number; removed: number } {
  let added = 0;
  let removed = 0;
  for (const line of diff.split("\n")) {
    if (line.startsWith("+++") || line.startsWith("---")) continue;
    if (line.startsWith("+")) added++;
    else if (line.startsWith("-")) removed++;
  }
  return { added, removed };
}

/**
 * Reject repo paths that escape the checkout or touch git internals. Returns
 * the normalized relative path, or null when unsafe.
 */
export function safeRepoRelativePath(p: string): string | null {
  const norm = p
    .trim()
    .replace(/\\/g, "/")
    .replace(/^\.\/+/, "")
    .replace(/^\/+/, "");
  if (!norm || norm.includes("\0")) return null;
  const parts = norm.split("/");
  if (parts.some((s) => s === ".." || s === "")) return null;
  if (parts[0] === ".git") return null;
  return parts.join("/");
}

const COMMENT_OR_TRIVIAL = /^(\/\/|#|\/\*|\*|<!--|--|[{}()[\];,]+$)/;

function identifiers(line: string): Set<string> {
  return new Set(line.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) ?? []);
}

function similar(a: Set<string>, b: Set<string>): boolean {
  if (a.size === 0) return false;
  let shared = 0;
  for (const t of a) if (b.has(t)) shared++;
  return shared / a.size >= 0.6;
}

/**
 * Removed code lines that have no similar line among the additions — i.e. code
 * the fix deleted outright rather than rewrote. A security fix should almost
 * never do that; deleting a neighbouring statement "fixes" nothing and breaks
 * behaviour. Comments, blank lines and bare brackets are ignored.
 */
export function unrelatedDeletions(
  diff: string,
): Array<{ path: string; line: number; text: string }> {
  const removed: Array<{ path: string; line: number; text: string }> = [];
  const added: Array<Set<string>> = [];
  let path = "";
  let oldLine = 0;
  for (const line of diff.split("\n")) {
    if (line.startsWith("--- ")) {
      path = line.replace(/^--- (a\/)?/, "");
      continue;
    }
    if (line.startsWith("+++ ")) {
      if (path === "/dev/null") path = line.replace(/^\+\+\+ (b\/)?/, "");
      continue;
    }
    const hunk = line.match(/^@@ -(\d+)/);
    if (hunk) {
      oldLine = Number(hunk[1]);
      continue;
    }
    const body = line.slice(1).trim();
    const countable = body && !COMMENT_OR_TRIVIAL.test(body);
    if (line.startsWith("-")) {
      if (countable) removed.push({ path, line: oldLine, text: body });
      oldLine++;
    } else if (line.startsWith("+")) {
      if (countable) added.push(identifiers(body));
    } else {
      oldLine++;
    }
  }
  return removed.filter((r) => {
    const ids = identifiers(r.text);
    return ids.size > 0 && !added.some((a) => similar(ids, a));
  });
}

/** Phrases models use when they elide code instead of writing it out. */
const PLACEHOLDER_PATTERNS = [
  /\.\.\.\s*(rest of|remaining|existing|unchanged) (the )?(code|file|implementation)/i,
  /\/\/\s*\.\.\.\s*(existing|rest|unchanged)/i,
  /#\s*\.\.\.\s*(existing|rest|unchanged)/i,
  /<!--\s*\.\.\.\s*(existing|rest|unchanged)/i,
];

/** True when the added lines of a diff contain an elision placeholder. */
export function diffHasPlaceholder(diff: string): boolean {
  return diff
    .split("\n")
    .filter((l) => l.startsWith("+") && !l.startsWith("+++"))
    .some((l) => PLACEHOLDER_PATTERNS.some((re) => re.test(l)));
}
