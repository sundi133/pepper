// Shared helpers for the standalone HTML report downloads (executive and
// compliance). Pages are self-contained: inline CSS only, no scripts, so they
// can be served under `default-src 'none'; style-src 'unsafe-inline'`.

export const REPORT_HTML_CSP = "default-src 'none'; style-src 'unsafe-inline'";

export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function formatReportDate(date: Date): string {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function reportFileSlug(name: string | null | undefined): string {
  return (name || "scan").replace(/[^a-zA-Z0-9_-]/g, "_");
}

export const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

export function severityRank(sev: string | null | undefined): number {
  return SEVERITY_ORDER[(sev || "").toUpperCase()] ?? 5;
}

const BASE_CSS = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.55; color: #1a1a2e; background: #f3f4f6; padding: 2rem 1rem; }
  .container { max-width: 960px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.08); overflow: hidden; }
  .hero { background: #1e3a5f; color: #fff; padding: 2rem; }
  .hero .eyebrow { font-size: 0.72rem; letter-spacing: 0.12em; text-transform: uppercase; color: #94a3b8; }
  .hero h1 { font-size: 1.75rem; margin: 0.35rem 0; }
  .hero .sub { color: #cbd5e1; font-size: 0.875rem; }
  .content { padding: 2rem; }
  h2 { font-size: 1rem; text-transform: uppercase; letter-spacing: 0.06em; color: #1e3a5f; border-left: 4px solid #1e3a5f; padding-left: 0.6rem; margin: 2rem 0 0.9rem; }
  h2:first-child { margin-top: 0; }
  h3 { font-size: 1rem; margin: 1.25rem 0 0.5rem; }
  p { margin-bottom: 0.6rem; }
  .muted { color: #6b7280; font-size: 0.85rem; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.75rem; margin: 0.75rem 0; }
  .card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 0.85rem; text-align: center; }
  .card .n { font-size: 1.6rem; font-weight: 700; font-variant-numeric: tabular-nums; }
  .card .l { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em; color: #6b7280; }
  .callout { border: 1px solid #e5e7eb; background: #f9fafb; border-radius: 8px; padding: 1rem; display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }
  .pill { display: inline-block; padding: 0.25rem 0.7rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; white-space: nowrap; }
  .sev-critical { background: #fee2e2; color: #b91c1c; }
  .sev-high { background: #ffedd5; color: #c2410c; }
  .sev-medium { background: #fef3c7; color: #b45309; }
  .sev-low { background: #dbeafe; color: #1d4ed8; }
  .sev-info { background: #f3f4f6; color: #4b5563; }
  .ok { background: #d1fae5; color: #047857; }
  .solid-critical { background: #dc2626; color: #fff; }
  .solid-high { background: #ea580c; color: #fff; }
  .solid-medium { background: #d97706; color: #fff; }
  .solid-low { background: #059669; color: #fff; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin: 0.5rem 0 1rem; }
  th { text-align: left; background: #1e3a5f; color: #fff; font-weight: 600; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.04em; padding: 0.5rem 0.6rem; }
  td { padding: 0.5rem 0.6rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; overflow-wrap: anywhere; }
  tr:nth-child(even) td { background: #f9fafb; }
  td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
  .bar-row { display: grid; grid-template-columns: 170px 1fr 48px; gap: 0.6rem; align-items: center; margin: 0.35rem 0; font-size: 0.85rem; }
  .bar-track { background: #f3f4f6; border-radius: 4px; height: 14px; overflow: hidden; }
  .bar-fill { background: #6ea8d9; height: 100%; border-radius: 4px; }
  .bar-row .v { text-align: right; font-variant-numeric: tabular-nums; }
  .grid3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.75rem; }
  .col { border: 1px solid #e5e7eb; border-radius: 8px; padding: 0.85rem; }
  .col h4 { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.5rem; }
  ul.tight { margin-left: 1.1rem; font-size: 0.85rem; color: #374151; }
  ul.tight li { margin: 0.25rem 0; }
  .chips { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0.5rem 0; }
  .chip { border: 1px solid #e5e7eb; border-radius: 6px; padding: 0.25rem 0.55rem; font-size: 0.75rem; }
  .footer { padding: 1rem 2rem 1.5rem; border-top: 1px solid #e5e7eb; text-align: center; color: #6b7280; font-size: 0.78rem; }
  @media (max-width: 600px) { .content, .hero { padding: 1.25rem; } .bar-row { grid-template-columns: 110px 1fr 40px; } }
  @media print { body { background: #fff; padding: 0; } .container { box-shadow: none; border-radius: 0; } h2 { break-after: avoid; } tr, .col, .card { break-inside: avoid; } }
`;

export function renderReportShell(opts: {
  title: string;
  eyebrow: string;
  heading: string;
  subtitle: string;
  body: string;
  footer: string;
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(opts.title)}</title>
  <style>${BASE_CSS}</style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <div class="eyebrow">${escapeHtml(opts.eyebrow)}</div>
      <h1>${escapeHtml(opts.heading)}</h1>
      <div class="sub">${opts.subtitle}</div>
    </div>
    <div class="content">${opts.body}</div>
    <div class="footer">${escapeHtml(opts.footer)}</div>
  </div>
</body>
</html>`;
}

export function loadPdfKit(): new (
  options?: PDFKit.PDFDocumentOptions,
) => PDFKit.PDFDocument {
  // Dynamic require to avoid webpack bundling pdfkit's fs-dependent font loading
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require("pdfkit");
}
