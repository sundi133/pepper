/**
 * Allowlist HTML sanitizer for AI-generated report bodies. Reports are shared
 * outside Pepper, so the stored HTML must not run code or load anything:
 *   - only formatting tags survive; script-like elements are dropped with
 *     their content, any other unknown tag is dropped but keeps its text;
 *   - every attribute is dropped except a short allowlist (class, colspan,
 *     rowspan, and href on links — http(s) only, no javascript:/data:);
 *   - no element that fetches (img, link, iframe, object, …) is allowed.
 * The Markdown renderer already escapes everything; this is a second,
 * independent layer applied to the final body.
 */
import { escapeHtml } from "@/lib/reports/report-html";
import { safeLinkHref } from "./markdown";

const ALLOWED_TAGS = new Set([
  "h1", "h2", "h3", "h4", "h5", "h6", "p", "br", "hr", "ul", "ol", "li",
  "strong", "b", "em", "i", "code", "pre", "blockquote", "table", "thead",
  "tbody", "tr", "th", "td", "a", "span", "div", "section", "sup", "sub",
]);

const VOID_TAGS = new Set(["br", "hr"]);

/** Dropped together with everything inside them. */
const DROP_WITH_CONTENT = new Set([
  "script", "style", "iframe", "object", "embed", "svg", "math", "template",
  "noscript", "textarea", "title", "head", "frameset", "frame", "applet",
  "audio", "video", "canvas", "select", "button", "form",
]);

const TOKEN_RE = /<!--[\s\S]*?(?:-->|$)|<(\/?)([a-zA-Z][a-zA-Z0-9-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>|<|[^<]+/g;
const ATTR_RE = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

function decodeAttr(value: string): string {
  return value
    .replace(/&#x([0-9a-f]+);?/gi, (_, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);?/g, (_, d: string) => String.fromCodePoint(Number(d)))
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function cleanAttributes(tag: string, raw: string): string {
  const out: string[] = [];
  let m: RegExpExecArray | null;
  ATTR_RE.lastIndex = 0;
  while ((m = ATTR_RE.exec(raw))) {
    const name = m[1].toLowerCase();
    const value = decodeAttr(m[2] ?? m[3] ?? m[4] ?? "");
    if (name === "href" && tag === "a") {
      const safe = safeLinkHref(value);
      if (safe) out.push(`href="${escapeHtml(safe)}"`, 'rel="noopener noreferrer nofollow"');
    } else if (name === "class" && /^[a-zA-Z0-9 _-]{1,80}$/.test(value)) {
      out.push(`class="${value}"`);
    } else if ((name === "colspan" || name === "rowspan") && (tag === "td" || tag === "th") && /^\d{1,2}$/.test(value)) {
      out.push(`${name}="${value}"`);
    }
  }
  return out.length ? ` ${out.join(" ")}` : "";
}

export function sanitizeReportHtml(html: string): string {
  const out: string[] = [];
  const open: string[] = [];
  let dropping: string | null = null;
  let dropDepth = 0;
  let m: RegExpExecArray | null;
  TOKEN_RE.lastIndex = 0;
  while ((m = TOKEN_RE.exec(html))) {
    const token = m[0];
    if (token.startsWith("<!--")) continue;
    const tagName = m[2]?.toLowerCase();
    if (!tagName) {
      if (dropping) continue;
      // A bare "<" that did not start a tag; text runs are kept verbatim
      // except for a stray ">" (harmless, but normalised).
      out.push(token === "<" ? "&lt;" : token.replace(/>/g, "&gt;"));
      continue;
    }
    const closing = m[1] === "/";
    if (dropping) {
      if (tagName === dropping) {
        dropDepth += closing ? -1 : 1;
        if (dropDepth === 0) dropping = null;
      }
      continue;
    }
    if (DROP_WITH_CONTENT.has(tagName)) {
      if (!closing && !/\/\s*$/.test(m[3] ?? "")) {
        dropping = tagName;
        dropDepth = 1;
      }
      continue;
    }
    if (!ALLOWED_TAGS.has(tagName)) continue;
    if (closing) {
      const idx = open.lastIndexOf(tagName);
      if (idx < 0) continue;
      // Close anything left open inside it so the structure stays balanced.
      while (open.length > idx) out.push(`</${open.pop()}>`);
      continue;
    }
    out.push(`<${tagName}${cleanAttributes(tagName, m[3] ?? "")}>`);
    if (!VOID_TAGS.has(tagName)) open.push(tagName);
  }
  while (open.length) out.push(`</${open.pop()}>`);
  return out.join("");
}
