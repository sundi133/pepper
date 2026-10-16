/**
 * A small Markdown dialect for custom reports: parsed into blocks once, then
 * rendered to HTML (here) or PDF (./pdf). Covers what report templates and the
 * model's answers use — headings, paragraphs, lists, tables, quotes, code and
 * rules — and nothing that can execute or fetch: raw HTML is never passed
 * through, images become their alt text, and only http(s) links survive.
 */
import { escapeHtml } from "@/lib/html-escape";

export type MdInline = string;

export type MdBlock =
  | { type: "heading"; level: number; text: MdInline }
  | { type: "paragraph"; text: MdInline }
  | { type: "list"; ordered: boolean; items: Array<{ text: MdInline; children: MdBlock[] }> }
  | { type: "table"; header: MdInline[]; rows: MdInline[][] }
  | { type: "quote"; blocks: MdBlock[] }
  | { type: "code"; text: string }
  | { type: "hr" };

const HEADING_RE = /^(#{1,6})\s+(.*?)\s*#*\s*$/;
const LIST_RE = /^(\s*)([-*+]|\d{1,3}[.)])\s+(.*)$/;
const HR_RE = /^\s{0,3}([-*_])(\s*\1){2,}\s*$/;
const FENCE_RE = /^\s*(```|~~~)/;
const TABLE_SEP_RE = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;

/**
 * Remove raw HTML from model-written Markdown before parsing: script/style
 * blocks with their content, comments, and every other tag (keeping its text).
 * `<br>` becomes a line break. What remains is escaped by the renderer anyway;
 * this only keeps stray tags from showing up as literal text.
 */
export function stripRawHtml(md: string): string {
  // Code (fenced blocks and inline spans) is shown verbatim — and escaped by
  // the renderer — so it is set aside before tags are removed.
  const kept: string[] = [];
  const hold = (s: string) => {
    kept.push(s);
    return `\u0001${kept.length - 1}\u0001`;
  };
  return md
    .replace(/^(\s*)(```|~~~)[^\n]*\n[\s\S]*?^\s*\2[^\n]*$/gm, hold)
    .replace(/`[^`\n]+`/g, hold)
    .replace(/<(script|style|iframe|object|embed|svg|math|template|noscript|textarea|head|title)\b[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/?[a-zA-Z][^<>]*>/g, "")
    .replace(/\u0001(\d+)\u0001/g, (_, n: string) => kept[Number(n)] ?? "");
}

function splitRow(line: string): string[] {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|") && !s.endsWith("\\|")) s = s.slice(0, -1);
  const cells: string[] = [];
  let cur = "";
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "\\" && s[i + 1] === "|") {
      cur += "|";
      i++;
    } else if (s[i] === "|") {
      cells.push(cur.trim());
      cur = "";
    } else cur += s[i];
  }
  cells.push(cur.trim());
  return cells;
}

function isBlockStart(line: string, next: string | undefined): boolean {
  return (
    HEADING_RE.test(line) ||
    LIST_RE.test(line) ||
    HR_RE.test(line) ||
    FENCE_RE.test(line) ||
    /^\s*>/.test(line) ||
    (line.includes("|") && next !== undefined && TABLE_SEP_RE.test(next))
  );
}

export function parseMarkdown(source: string): MdBlock[] {
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const blocks: MdBlock[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }
    const fence = line.match(FENCE_RE);
    if (fence) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith(fence[1])) body.push(lines[i++]);
      i++;
      blocks.push({ type: "code", text: body.join("\n") });
      continue;
    }
    const h = line.match(HEADING_RE);
    if (h) {
      blocks.push({ type: "heading", level: h[1].length, text: h[2] });
      i++;
      continue;
    }
    if (HR_RE.test(line)) {
      blocks.push({ type: "hr" });
      i++;
      continue;
    }
    if (line.includes("|") && i + 1 < lines.length && TABLE_SEP_RE.test(lines[i + 1])) {
      const header = splitRow(line);
      const rows: string[][] = [];
      i += 2;
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) {
        const cells = splitRow(lines[i++]);
        rows.push(header.map((_, c) => cells[c] ?? ""));
      }
      blocks.push({ type: "table", header, rows });
      continue;
    }
    if (/^\s*>/.test(line)) {
      const inner: string[] = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) inner.push(lines[i++].replace(/^\s*>\s?/, ""));
      blocks.push({ type: "quote", blocks: parseMarkdown(inner.join("\n")) });
      continue;
    }
    const li = line.match(LIST_RE);
    if (li) {
      const baseIndent = li[1].length;
      const ordered = /\d/.test(li[2]);
      const items: Array<{ text: string; children: MdBlock[] }> = [];
      while (i < lines.length) {
        const m = lines[i].match(LIST_RE);
        if (m && m[1].length <= baseIndent) {
          if (/\d/.test(m[2]) !== ordered) break;
          items.push({ text: m[3], children: [] });
          i++;
          // Indented continuation lines and nested lists belong to this item.
          const nested: string[] = [];
          while (i < lines.length && lines[i].trim() && /^\s+/.test(lines[i]) && (lines[i].match(/^\s*/)?.[0].length ?? 0) > baseIndent) {
            nested.push(lines[i++]);
          }
          if (nested.length) {
            const cut = Math.min(...nested.map((l) => l.match(/^\s*/)![0].length));
            const text = nested.map((l) => l.slice(cut));
            if (LIST_RE.test(text[0])) items[items.length - 1].children = parseMarkdown(text.join("\n"));
            else items[items.length - 1].text += ` ${text.join(" ").trim()}`;
          }
          continue;
        }
        break;
      }
      blocks.push({ type: "list", ordered, items });
      continue;
    }
    const para: string[] = [line.trim()];
    i++;
    while (i < lines.length && lines[i].trim() && !isBlockStart(lines[i], lines[i + 1])) para.push(lines[i++].trim());
    blocks.push({ type: "paragraph", text: para.join(" ") });
  }
  return blocks;
}

/** Only absolute http(s) links are kept; anything else renders as text. */
export function safeLinkHref(href: string): string | null {
  const clean = href.trim().replace(/[\u0000-\u001f\u007f\s]/g, "");
  return /^https?:\/\/[^\s"'<>]+$/i.test(clean) ? clean : null;
}

/** Render inline Markdown to escaped HTML. */
export function renderInline(text: string): string {
  // Code spans are cut out first so their contents are never formatted.
  const codes: string[] = [];
  let s = text.replace(/`([^`]+)`/g, (_, c: string) => {
    codes.push(`<code>${escapeHtml(c)}</code>`);
    return `\u0000${codes.length - 1}\u0000`;
  });
  s = escapeHtml(s);
  // Images: never load anything — keep the alt text only.
  s = s.replace(/!\[([^\]]*)\]\(([^)\s]*)[^)]*\)/g, "$1");
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (whole, label: string, href: string) => {
    const decoded = href.replace(/&amp;/g, "&");
    const safe = safeLinkHref(decoded);
    return safe ? `<a href="${escapeHtml(safe)}" rel="noopener noreferrer nofollow">${label}</a>` : label;
  });
  s = s.replace(/\*\*(?=\S)([\s\S]*?\S)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/__(?=\S)([\s\S]*?\S)__/g, "<strong>$1</strong>");
  s = s.replace(/(^|[^*\w])\*(?=\S)([^*]*?\S)\*(?!\*)/g, "$1<em>$2</em>");
  s = s.replace(/(^|[^_\w])_(?=\S)([^_]*?\S)_(?!\w)/g, "$1<em>$2</em>");
  return s.replace(/\u0000(\d+)\u0000/g, (_, n: string) => codes[Number(n)] ?? "");
}

/** Inline Markdown reduced to plain text (PDF output, titles). */
export function inlineToText(text: string): string {
  return text
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label: string, href: string) =>
      safeLinkHref(href) ? `${label} (${href})` : label,
    )
    .replace(/\*\*([\s\S]*?)\*\*|__([\s\S]*?)__/g, (_, a?: string, b?: string) => a ?? b ?? "")
    .replace(/(^|[^*\w])\*([^*]+)\*/g, "$1$2")
    .replace(/(^|[^_\w])_([^_]+)_(?!\w)/g, "$1$2")
    .replace(/`([^`]+)`/g, "$1");
}

export function renderBlocksHtml(blocks: MdBlock[]): string {
  return blocks
    .map((b) => {
      switch (b.type) {
        case "heading":
          return `<h${b.level}>${renderInline(b.text)}</h${b.level}>`;
        case "paragraph":
          return `<p>${renderInline(b.text)}</p>`;
        case "list": {
          const tag = b.ordered ? "ol" : "ul";
          const items = b.items
            .map((it) => `<li>${renderInline(it.text)}${it.children.length ? renderBlocksHtml(it.children) : ""}</li>`)
            .join("");
          return `<${tag}>${items}</${tag}>`;
        }
        case "table":
          return `<table><thead><tr>${b.header.map((c) => `<th>${renderInline(c)}</th>`).join("")}</tr></thead><tbody>${b.rows
            .map((r) => `<tr>${r.map((c) => `<td>${renderInline(c)}</td>`).join("")}</tr>`)
            .join("")}</tbody></table>`;
        case "quote":
          return `<blockquote>${renderBlocksHtml(b.blocks)}</blockquote>`;
        case "code":
          return `<pre><code>${escapeHtml(b.text)}</code></pre>`;
        case "hr":
          return "<hr>";
      }
    })
    .join("\n");
}

/** Markdown → escaped HTML fragment. Raw HTML in the source is dropped. */
export function renderMarkdownHtml(md: string): string {
  return renderBlocksHtml(parseMarkdown(stripRawHtml(md)));
}
