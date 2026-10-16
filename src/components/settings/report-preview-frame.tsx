"use client";

/** Minimal report styling for the preview (the full report uses the shared report shell). */
const PREVIEW_CSS = `
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 13px; line-height: 1.55; color: #1a1a2e; margin: 16px; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.05rem; color: #1e3a5f; border-left: 4px solid #1e3a5f; padding-left: .5rem; } h3 { font-size: .95rem; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0; } th { background: #1e3a5f; color: #fff; text-align: left; font-size: .75rem; padding: .35rem .5rem; } td { border-bottom: 1px solid #e5e7eb; padding: .35rem .5rem; }
  code { background: #f3f4f6; border-radius: 4px; padding: 0 3px; font-size: .85em; } pre { background: #f3f4f6; padding: .5rem; overflow-x: auto; }
  blockquote { border-left: 3px solid #e5e7eb; margin: .5rem 0; padding-left: .75rem; color: #4b5563; }
`;

/**
 * Render already-sanitized report HTML in a fully sandboxed frame (no
 * scripts, no same-origin access) so a preview can never act on the page.
 */
export function ReportPreviewFrame({ html, title }: { html: string; title?: string | null }) {
  const doc = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><style>${PREVIEW_CSS}</style></head><body>${html}</body></html>`;
  return (
    <iframe
      title={title ? `Preview: ${title}` : "Template preview"}
      sandbox=""
      srcDoc={doc}
      className="h-[420px] w-full rounded-lg border bg-white"
    />
  );
}
