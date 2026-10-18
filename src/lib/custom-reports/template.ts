/**
 * Report templates: normalisation to Markdown, section outline, and explicit
 * {{placeholders}}.
 *
 * A template needs no placeholders — its headings, sections, tables and
 * wording show the AI what to produce. Placeholders it does use are filled
 * deterministically from the scan before any AI step, so values such as
 * counts and the commit are exact rather than written by the model.
 */
import { stripRawHtml } from "./markdown";

export const TEMPLATE_FORMATS = ["markdown", "html", "text"] as const;
export type TemplateFormat = (typeof TEMPLATE_FORMATS)[number];

export const MAX_TEMPLATE_CHARS = 100_000;
export const MAX_INSTRUCTIONS_CHARS = 4_000;
/** Sections beyond this are merged into the last one (bounds AI calls). */
export const MAX_TEMPLATE_SECTIONS = 20;

// ─── HTML → Markdown ──────────────────────────────────────────────────

function decodeEntities(s: string): string {
  return s
    .replace(/&nbsp;/g, " ")
    .replace(/&#x([0-9a-f]+);/gi, (_, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d: string) => String.fromCodePoint(Number(d)))
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function cellText(html: string): string {
  return decodeEntities(html.replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").replace(/\|/g, "\\|").trim();
}

/**
 * Convert an HTML template to Markdown that keeps its structure: headings,
 * paragraphs, lists, tables and emphasis. Scripts, styles and attributes are
 * discarded — only the layout and wording matter to the AI.
 */
export function htmlToMarkdown(html: string): string {
  let s = html
    .replace(/<(script|style|head|title|noscript|template|svg)\b[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/<!--[\s\S]*?-->/g, "");

  s = s.replace(/<table\b[\s\S]*?<\/table\s*>/gi, (table) => {
    const rows = [...table.matchAll(/<tr\b[\s\S]*?<\/tr\s*>/gi)].map((r) =>
      [...r[0].matchAll(/<t([hd])\b[^>]*>([\s\S]*?)<\/t\1\s*>/gi)].map((c) => cellText(c[2])),
    );
    if (rows.length === 0) return "";
    const width = Math.max(...rows.map((r) => r.length));
    const pad = (r: string[]) => Array.from({ length: width }, (_, i) => r[i] ?? "");
    const [head, ...body] = rows;
    const line = (r: string[]) => `| ${pad(r).join(" | ")} |`;
    return `\n\n${[line(head), `| ${Array(width).fill("---").join(" | ")} |`, ...body.map(line)].join("\n")}\n\n`;
  });

  s = s
    .replace(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1\s*>/gi, (_, l: string, t: string) => `\n\n${"#".repeat(Number(l))} ${cellText(t).replace(/\\\|/g, "|")}\n\n`)
    .replace(/<li\b[^>]*>/gi, "\n- ")
    .replace(/<\/li\s*>/gi, "")
    .replace(/<\/?(ul|ol)\b[^>]*>/gi, "\n\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/?(strong|b)\b[^>]*>/gi, "**")
    .replace(/<\/?(em|i)\b[^>]*>/gi, "*")
    .replace(/<hr\b[^>]*>/gi, "\n\n---\n\n")
    .replace(/<\/?(p|div|section|article|header|footer|blockquote|main|body|html)\b[^>]*>/gi, "\n\n")
    .replace(/<[^>]+>/g, "");

  return decodeEntities(s)
    .split("\n")
    .map((l) => l.replace(/[ \t]+$/g, "").replace(/^[ \t]+(?=[^-\s])/, ""))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/** Any accepted template body → the Markdown the pipeline works on. */
export function normalizeTemplateBody(format: string, body: string): string {
  if (format === "html") return htmlToMarkdown(body);
  return stripRawHtml(body).replace(/\r\n?/g, "\n").trim();
}

/** Guess a format from a file name (uploads) — DOCX is converted separately. */
export function formatFromFileName(name: string): TemplateFormat | "docx" | null {
  const ext = name.toLowerCase().split(".").pop() ?? "";
  if (ext === "md" || ext === "markdown") return "markdown";
  if (ext === "html" || ext === "htm") return "html";
  if (ext === "txt" || ext === "text") return "text";
  if (ext === "docx") return "docx";
  return null;
}

// ─── Sections ─────────────────────────────────────────────────────────

export interface TemplateSection {
  index: number;
  /** Heading text as written in the template ("" for text before the first heading). */
  heading: string;
  level: number;
  /** The section's template content below its heading (guidance for the AI). */
  body: string;
}

/**
 * Split a template into the sections the agent writes one at a time. A
 * leading H1 (when no other H1 follows) is the document title, not a section.
 * A template without headings is a single section.
 */
export function templateSections(markdown: string): { title: string | null; sections: TemplateSection[] } {
  const lines = markdown.split("\n");
  const raw: Array<{ heading: string; level: number; body: string[] }> = [];
  let current: { heading: string; level: number; body: string[] } = { heading: "", level: 0, body: [] };
  let inFence = false;
  for (const line of lines) {
    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;
    const h = !inFence && line.match(/^(#{1,3})\s+(.*?)\s*#*\s*$/);
    if (h) {
      raw.push(current);
      current = { heading: h[2].trim(), level: h[1].length, body: [] };
    } else current.body.push(line);
  }
  raw.push(current);

  let title: string | null = null;
  const nonEmpty = raw.filter((r) => r.heading || r.body.join("\n").trim());
  // A leading H1 followed by other sections is the document title; any text
  // under it becomes the introduction.
  if (nonEmpty[0]?.level === 1 && nonEmpty.length > 1 && !nonEmpty.slice(1).some((r) => r.level === 1)) {
    const first = nonEmpty.shift()!;
    title = first.heading;
    if (first.body.join("\n").trim()) nonEmpty.unshift({ heading: "", level: 0, body: first.body });
  }
  let sections = nonEmpty.map((r, index) => ({
    index,
    heading: r.heading,
    level: r.level || 2,
    body: r.body.join("\n").trim(),
  }));
  if (sections.length > MAX_TEMPLATE_SECTIONS) {
    const head = sections.slice(0, MAX_TEMPLATE_SECTIONS - 1);
    const rest = sections.slice(MAX_TEMPLATE_SECTIONS - 1);
    const merged = rest
      .map((s) => (s.heading ? `${"#".repeat(Math.min(6, s.level + 1))} ${s.heading}\n\n${s.body}` : s.body))
      .join("\n\n");
    sections = [...head, { ...rest[0], index: MAX_TEMPLATE_SECTIONS - 1, body: merged }];
  }
  if (sections.length === 0) sections = [{ index: 0, heading: "", level: 2, body: "" }];
  return { title, sections };
}

// ─── Placeholders ─────────────────────────────────────────────────────

export const PLACEHOLDER_RE = /\{\{\s*([a-zA-Z][a-zA-Z0-9_.]*)\s*\}\}/g;

/** Every placeholder the filler knows, with what it stands for. */
export const PLACEHOLDERS: Record<string, string> = {
  "scan.id": "Scan ID",
  "scan.repository": "Repository (project) name",
  "scan.repository_url": "Repository URL",
  "scan.branch": "Branch scanned",
  "scan.commit": "Commit SHA scanned",
  "scan.type": "Scan type (FULL, SAST_ONLY, …)",
  "scan.status": "Scan status",
  "scan.date": "When the scan completed (or started)",
  "scan.gate_result": "Build gate result",
  "scan.files_scanned": "Files scanned",
  "scan.dependencies_scanned": "Dependencies scanned",
  "findings.total": "Findings, excluding false positives",
  "findings.open_count": "Open + in-progress findings",
  "findings.critical_count": "Critical findings (excluding false positives)",
  "findings.high_count": "High findings (excluding false positives)",
  "findings.medium_count": "Medium findings (excluding false positives)",
  "findings.low_count": "Low findings (excluding false positives)",
  "findings.info_count": "Info findings (excluding false positives)",
  "findings.new_count": "Findings new since the previous scan",
  "findings.fixed_count": "Findings fixed since the previous scan",
  "findings.false_positive_count": "Findings marked false positive",
  "report.date": "When the report was generated",
};

/** Distinct placeholder names used in a text, split into known and unknown. */
export function findPlaceholders(text: string): { known: string[]; unknown: string[] } {
  const names = new Set([...text.matchAll(PLACEHOLDER_RE)].map((m) => m[1]));
  const known: string[] = [];
  const unknown: string[] = [];
  for (const n of names) (n in PLACEHOLDERS ? known : unknown).push(n);
  return { known, unknown };
}

/**
 * Replace placeholders with their values. Unknown names (or known names with
 * no value for this scan) become `fallback`, so the AI never sees braces it
 * might try to "fill in" itself.
 */
export function fillPlaceholders(
  text: string,
  values: Record<string, string | number | null | undefined>,
  fallback = "n/a",
): string {
  return text.replace(PLACEHOLDER_RE, (_, name: string) => {
    const v = values[name];
    return v === null || v === undefined || v === "" ? fallback : String(v);
  });
}
