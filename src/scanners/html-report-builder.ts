import type { RawFinding } from "./types";
import { buildScanMarkdownReport, type ProjectLike, type ScanLike } from "./reports/scan-markdown-report-builder";

export function buildHtmlFindingsReport(input: {
  scan: ScanLike & {
    startedAt?: Date | null;
    completedAt?: Date | null;
    filesScanned?: number;
    depsScanned?: number;
    gateResult?: string;
  };
  project: ProjectLike;
  findings: RawFinding[];
}): string {
  const markdown = buildScanMarkdownReport(input);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SAST Findings Report</title>
  <style>${css()}</style>
</head>
<body>
  <main class="report">
    ${renderMarkdown(markdown)}
  </main>
</body>
</html>`;
}

function renderMarkdown(markdown: string): string {
  const lines = markdown.split(/\r?\n/);
  const html: string[] = [];
  let inCode = false;
  let inTable = false;
  let inList = false;
  let inOrderedList = false;

  const closeList = () => {
    if (inList) {
      html.push("</ul>");
      inList = false;
    }
    if (inOrderedList) {
      html.push("</ol>");
      inOrderedList = false;
    }
  };
  const closeTable = () => {
    if (inTable) {
      html.push("</tbody></table>");
      inTable = false;
    }
  };

  for (const line of lines) {
    if (line.startsWith("```")) {
      closeList();
      closeTable();
      if (!inCode) {
        inCode = true;
        html.push(`<pre><code>`);
      } else {
        inCode = false;
        html.push(`</code></pre>`);
      }
      continue;
    }
    if (inCode) {
      html.push(escapeHtml(line));
      continue;
    }
    if (/^\|.*\|$/.test(line.trim())) {
      closeList();
      const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
      if (cells.every((cell) => /^-+:?$/.test(cell.replace(/\s/g, "")))) continue;
      if (!inTable) {
        inTable = true;
        html.push("<table><tbody>");
      }
      html.push(`<tr>${cells.map((cell) => `<td>${inline(cell)}</td>`).join("")}</tr>`);
      continue;
    }
    closeTable();
    if (line.startsWith("- ")) {
      if (inOrderedList) {
        html.push("</ol>");
        inOrderedList = false;
      }
      if (!inList) {
        inList = true;
        html.push("<ul>");
      }
      html.push(`<li>${inline(line.slice(2))}</li>`);
      continue;
    }
    const ordered = line.match(/^\d+\.\s+(.+)$/);
    if (ordered) {
      if (inList) {
        html.push("</ul>");
        inList = false;
      }
      if (!inOrderedList) {
        inOrderedList = true;
        html.push("<ol>");
      }
      html.push(`<li>${inline(ordered[1])}</li>`);
      continue;
    }
    closeList();
    if (line.startsWith("# ")) html.push(`<h1>${inline(line.slice(2))}</h1>`);
    else if (line.startsWith("## ")) html.push(`<h2>${inline(line.slice(3))}</h2>`);
    else if (line.startsWith("### ")) html.push(`<h3>${inline(line.slice(4))}</h3>`);
    else if (line.trim()) html.push(`<p>${inline(line)}</p>`);
  }
  closeList();
  closeTable();
  if (inCode) html.push("</code></pre>");
  return html.join("\n");
}

function inline(value: string): string {
  return escapeHtml(value)
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
}

function css(): string {
  return `
    :root{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--panel:#fff;--bg:#f8fafc;--brand:#2563eb}
    *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.6}
    .report{max-width:980px;margin:0 auto;padding:36px 24px 64px}
    h1{margin:0 0 18px;font-size:34px;letter-spacing:-.04em}
    h2{margin:34px 0 14px;font-size:24px;letter-spacing:-.02em;border-top:1px solid var(--line);padding-top:22px}
    h3{margin:30px 0 14px;border-left:6px solid var(--brand);border-radius:12px;background:var(--panel);padding:16px 18px;font-size:21px;box-shadow:0 10px 30px rgba(15,23,42,.06)}
    p{margin:8px 0 14px}.report>p:nth-of-type(-n+6){color:var(--muted)}
    strong{color:#111827} code{border:1px solid #dbe3ef;border-radius:6px;background:#f1f5f9;padding:1px 5px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:.92em}
    pre{margin:16px 0 22px;overflow:auto;border:1px solid #1e293b;border-radius:16px;background:#0f172a;padding:18px;color:#e2e8f0;box-shadow:0 12px 28px rgba(15,23,42,.12)}
    pre code{border:0;background:transparent;color:inherit;padding:0;white-space:pre;font-size:13px;line-height:1.55}
    table{width:100%;margin:18px 0 24px;border-collapse:collapse;border:1px solid var(--line);border-radius:14px;overflow:hidden;background:var(--panel)}
    td{border-bottom:1px solid var(--line);padding:10px 12px} tr:first-child td{font-weight:800;background:#f1f5f9} tr:last-child td{border-bottom:0} td:last-child{text-align:right}
    ul{margin:10px 0 18px;padding-left:22px} li{margin:6px 0}
    @media print{body{background:#fff}.report{max-width:none;padding:0}h3,pre,table{break-inside:avoid;box-shadow:none}}
  `;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
