import {
  escapeHtml,
  formatReportDate,
  loadPdfKit,
  renderReportShell,
  severityRank,
} from "./report-html";

// Shape of a cached per-framework report (see buildFrameworkReport in
// @/lib/compliance/report-run). Typed loosely because older cache entries may
// predate the coverage buckets.
type ControlRef = {
  controlId: string;
  title: string;
  theme?: string;
  relevance?: string;
  reasoning?: string;
};

type BucketEntry = {
  controlId: string;
  title: string;
  theme?: string;
  coverage?: string;
  findingCount: number;
  criticalHighCount: number;
  reason?: string;
};

export type ComplianceFrameworkReport = {
  framework: string;
  version?: string | null;
  mappingSource?: string;
  totalControls: number;
  impactedControls: number;
  buckets?: {
    gapsFound: BucketEntry[];
    noIssuesDetected: BucketEntry[];
    notCovered: BucketEntry[];
  };
  findings: {
    id: string;
    title?: string | null;
    severity?: string | null;
    filePath?: string | null;
    startLine?: number | null;
    status?: string | null;
    controls: ControlRef[];
  }[];
};

export type ComplianceExportInput = {
  projectName: string;
  repoUrl: string | null;
  commitSha: string | null;
  scanDate: Date;
  mode: "deep" | "fast";
  model: string | null;
  totalFindings: number;
  reports: ComplianceFrameworkReport[];
};

const SOURCE_LABELS: Record<string, string> = {
  agentic: "Agentic AI mapping (verified)",
  crosswalk: "Deterministic CWE crosswalk",
  llm: "AI mapping",
};

function frameworkStats(r: ComplianceFrameworkReport) {
  const gaps = r.buckets?.gapsFound.length ?? r.impactedControls;
  const clear = r.buckets?.noIssuesDetected.length ?? 0;
  const notCovered = r.buckets?.notCovered.length ?? Math.max(0, r.totalControls - gaps - clear);
  const assessed = gaps + clear;
  // Share of SAST-assessable controls where no issues were detected.
  const passRate = assessed > 0 ? Math.round((clear / assessed) * 100) : null;
  return { gaps, clear, notCovered, assessed, passRate };
}

function mappedFindings(r: ComplianceFrameworkReport) {
  return r.findings
    .filter((f) => f.controls.length > 0)
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

function location(f: { filePath?: string | null; startLine?: number | null }): string {
  if (!f.filePath) return "";
  return f.startLine ? `${f.filePath}:${f.startLine}` : f.filePath;
}

function modeLabel(input: ComplianceExportInput): string {
  if (input.mode === "fast") return "Fast (deterministic crosswalk)";
  return input.model ? `Agentic · ${input.model}` : "Agentic";
}

// ─── HTML ───────────────────────────────────────────────────────────
function sevPill(sev: string | null | undefined): string {
  const s = (sev || "INFO").toLowerCase();
  const cls = ["critical", "high", "medium", "low"].includes(s) ? `sev-${s}` : "sev-info";
  return `<span class="pill ${cls}">${escapeHtml(s.toUpperCase())}</span>`;
}

function renderFrameworkHtml(r: ComplianceFrameworkReport): string {
  const st = frameworkStats(r);
  const gaps = r.buckets?.gapsFound ?? [];
  const findings = mappedFindings(r);

  const gapsTable = gaps.length
    ? `<table>
        <thead><tr><th style="width:110px">Control</th><th>Title</th><th style="width:140px">Theme</th><th class="num" style="width:80px">Findings</th><th class="num" style="width:90px">Crit/High</th></tr></thead>
        <tbody>${gaps
          .map(
            (g) => `<tr>
              <td><strong>${escapeHtml(g.controlId)}</strong></td>
              <td>${escapeHtml(g.title)}</td>
              <td>${escapeHtml(g.theme || "")}</td>
              <td class="num">${g.findingCount}</td>
              <td class="num">${g.criticalHighCount > 0 ? `<span class="pill sev-critical">${g.criticalHighCount}</span>` : "0"}</td>
            </tr>`,
          )
          .join("")}</tbody>
      </table>`
    : `<p class="muted">No control gaps were found for this framework.</p>`;

  const findingsTable = findings.length
    ? `<table>
        <thead><tr><th>Finding</th><th style="width:95px">Severity</th><th style="width:260px">Controls</th></tr></thead>
        <tbody>${findings
          .map(
            (f) => `<tr>
              <td><strong>${escapeHtml(f.title || f.id)}</strong>${location(f) ? `<div class="muted">${escapeHtml(location(f))}</div>` : ""}</td>
              <td>${sevPill(f.severity)}</td>
              <td>${f.controls
                .map(
                  (c) =>
                    `<div><strong>${escapeHtml(c.controlId)}</strong> ${escapeHtml(c.title)}${c.relevance ? ` <span class="muted">(${escapeHtml(c.relevance)})</span>` : ""}</div>`,
                )
                .join("")}</td>
            </tr>`,
          )
          .join("")}</tbody>
      </table>`
    : `<p class="muted">No findings were mapped to this framework's controls.</p>`;

  const clearChips = (r.buckets?.noIssuesDetected ?? [])
    .map((c) => `<span class="chip ok" title="${escapeHtml(c.title)}">${escapeHtml(c.controlId)}</span>`)
    .join("");

  const notCovered = r.buckets?.notCovered ?? [];
  const notCoveredList = notCovered.length
    ? `<ul class="tight">${notCovered
        .map(
          (c) =>
            `<li><strong>${escapeHtml(c.controlId)}</strong> ${escapeHtml(c.title)}${c.reason ? ` <span class="muted">— ${escapeHtml(c.reason)}</span>` : ""}</li>`,
        )
        .join("")}</ul>`
    : "";

  return `
    <h2>${escapeHtml(r.framework)}${r.version ? ` <span class="muted" style="text-transform:none;letter-spacing:0">${escapeHtml(r.version)}</span>` : ""}</h2>
    <p class="muted">${escapeHtml(SOURCE_LABELS[r.mappingSource || ""] || r.mappingSource || "")} · ${r.totalControls} controls</p>
    <div class="cards">
      <div class="card"><div class="n" style="color:#dc2626">${st.gaps}</div><div class="l">Controls with gaps</div></div>
      <div class="card"><div class="n" style="color:#059669">${st.clear}</div><div class="l">No issues detected</div></div>
      <div class="card"><div class="n" style="color:#6b7280">${st.notCovered}</div><div class="l">Not assessable by SAST</div></div>
      <div class="card"><div class="n">${st.passRate == null ? "—" : `${st.passRate}%`}</div><div class="l">Assessable controls clear</div></div>
    </div>
    <h3>Control gaps</h3>
    ${gapsTable}
    <h3>Findings mapped to controls (${findings.length})</h3>
    ${findingsTable}
    ${clearChips ? `<h3>Controls with no issues detected</h3><div class="chips">${clearChips}</div>` : ""}
    ${notCoveredList ? `<h3>Requires evidence outside the codebase</h3>${notCoveredList}` : ""}
  `;
}

export function buildComplianceHtml(input: ComplianceExportInput): string {
  const overview = input.reports
    .map((r) => {
      const st = frameworkStats(r);
      return `<tr>
        <td><strong>${escapeHtml(r.framework)}</strong>${r.version ? ` <span class="muted">${escapeHtml(r.version)}</span>` : ""}</td>
        <td class="num">${r.totalControls}</td>
        <td class="num">${st.gaps}</td>
        <td class="num">${st.clear}</td>
        <td class="num">${st.notCovered}</td>
        <td class="num">${st.passRate == null ? "—" : `${st.passRate}%`}</td>
      </tr>`;
    })
    .join("");

  const body = `
    <h2>Overview</h2>
    <p class="muted">${input.reports.length} framework${input.reports.length === 1 ? "" : "s"} assessed against ${input.totalFindings} findings · Mapping mode: ${escapeHtml(modeLabel(input))}${input.commitSha ? ` · Commit ${escapeHtml(input.commitSha.slice(0, 12))}` : ""}</p>
    <table>
      <thead><tr><th>Framework</th><th class="num">Controls</th><th class="num">Gaps</th><th class="num">Clear</th><th class="num">Not assessable</th><th class="num">Clear rate</th></tr></thead>
      <tbody>${overview}</tbody>
    </table>
    <p class="muted">Static analysis can only evidence technical controls. Controls marked "not assessable" require process, physical or organizational evidence and are out of scope for this report.</p>
    ${input.reports.map(renderFrameworkHtml).join("")}
  `;

  return renderReportShell({
    title: `Compliance Report — ${input.projectName}`,
    eyebrow: "Confidential · Compliance assessment",
    heading: "Compliance Report",
    subtitle: `${escapeHtml(input.projectName)} · ${escapeHtml(formatReportDate(input.scanDate))}${input.repoUrl ? `<br>${escapeHtml(input.repoUrl)}` : ""}`,
    body,
    footer: `Generated ${formatReportDate(new Date())} by Pepper · Confidential — for the authorized recipient only.`,
  });
}

// ─── PDF ────────────────────────────────────────────────────────────
const C = {
  header: "#1e3a5f",
  text: "#1a1a2e",
  secondary: "#4b5563",
  muted: "#6b7280",
  border: "#e5e7eb",
  light: "#f9fafb",
  white: "#ffffff",
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  green: "#059669",
  greenBg: "#d1fae5",
};

function sevColor(sev: string | null | undefined): string {
  switch ((sev || "").toUpperCase()) {
    case "CRITICAL": return C.critical;
    case "HIGH": return C.high;
    case "MEDIUM": return C.medium;
    case "LOW": return C.low;
    default: return C.muted;
  }
}

export function buildCompliancePdf(input: ComplianceExportInput): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const PDFDocument = loadPdfKit();
      const chunks: Buffer[] = [];
      const doc = new PDFDocument({
        size: "A4",
        margins: { top: 50, bottom: 50, left: 50, right: 50 },
        info: {
          Title: `Compliance Report — ${input.projectName}`,
          Author: "Pepper SAST",
          Subject: "Compliance Assessment",
        },
      });
      doc.on("data", (chunk: Buffer) => chunks.push(chunk));
      doc.on("end", () => resolve(Buffer.concat(chunks)));
      doc.on("error", reject);

      const pageW = 595.28;
      const x0 = 50;
      const w = pageW - 100;
      const bottom = 790;
      let y = 0;

      const ensure = (h: number) => {
        if (y + h > bottom) {
          doc.addPage();
          y = 50;
        }
      };
      const section = (title: string, minBody = 60) => {
        ensure(30 + minBody);
        y += 8;
        doc.rect(x0, y, 4, 16).fill(C.header);
        doc.fontSize(10).fillColor(C.text).text(title, x0 + 12, y + 2, { width: w - 12 });
        y = Math.max(y + 26, doc.y + 8);
      };
      const subheading = (title: string) => {
        ensure(40);
        doc.fontSize(9).fillColor(C.header).text(title.toUpperCase(), x0, y, { width: w });
        y = doc.y + 5;
      };

      // Generic table with wrapping cells and a repeated header on page breaks.
      const table = (
        headers: string[],
        widths: number[],
        rows: { cells: string[]; colors?: (string | undefined)[] }[],
      ) => {
        const drawHeader = () => {
          doc.rect(x0, y, w, 18).fill(C.header);
          doc.fontSize(7).fillColor(C.white);
          let cx = x0;
          headers.forEach((h, i) => {
            doc.text(h, cx + 5, y + 6, { width: widths[i] - 10 });
            cx += widths[i];
          });
          y += 18;
        };
        ensure(40);
        drawHeader();
        rows.forEach((row, idx) => {
          doc.fontSize(8);
          const heights = row.cells.map((c, i) => doc.heightOfString(c, { width: widths[i] - 10 }));
          const rowH = Math.max(18, Math.max(...heights) + 10);
          if (y + rowH > bottom) {
            doc.addPage();
            y = 50;
            drawHeader();
          }
          doc.rect(x0, y, w, rowH).fill(idx % 2 === 0 ? C.white : C.light);
          let cx = x0;
          row.cells.forEach((c, i) => {
            doc.fontSize(8).fillColor(row.colors?.[i] || C.text).text(c, cx + 5, y + 5, { width: widths[i] - 10 });
            cx += widths[i];
          });
          y += rowH;
        });
        y += 8;
      };

      // Header band
      doc.rect(0, 0, pageW, 120).fill(C.header);
      doc.fontSize(9).fillColor("#94a3b8").text("CONFIDENTIAL  ·  COMPLIANCE ASSESSMENT", x0, 28, { width: w });
      doc.fontSize(24).fillColor(C.white).text("Compliance Report", x0, 48, { width: w });
      doc.fontSize(10).fillColor("#cbd5e1")
        .text(`${input.projectName} · ${formatReportDate(input.scanDate)}`, x0, 84, { width: w });
      if (input.repoUrl) {
        doc.fontSize(8).fillColor("#94a3b8").text(input.repoUrl, x0, 100, { width: w, lineBreak: false, ellipsis: true });
      }
      y = 140;

      // Overview
      section("OVERVIEW");
      doc.fontSize(8.5).fillColor(C.secondary).text(
        `${input.reports.length} framework${input.reports.length === 1 ? "" : "s"} assessed against ${input.totalFindings} findings · Mapping mode: ${modeLabel(input)}` +
          (input.commitSha ? ` · Commit ${input.commitSha.slice(0, 12)}` : ""),
        x0, y, { width: w },
      );
      y = doc.y + 8;
      table(
        ["FRAMEWORK", "CONTROLS", "GAPS", "CLEAR", "OUT OF SCOPE", "CLEAR RATE"],
        [w - 5 * 66, 66, 66, 66, 66, 66],
        input.reports.map((r) => {
          const st = frameworkStats(r);
          return {
            cells: [
              `${r.framework}${r.version ? ` (${r.version})` : ""}`,
              String(r.totalControls),
              String(st.gaps),
              String(st.clear),
              String(st.notCovered),
              st.passRate == null ? "—" : `${st.passRate}%`,
            ],
            colors: [undefined, undefined, st.gaps > 0 ? C.critical : undefined, C.green],
          };
        }),
      );
      doc.fontSize(7.5).fillColor(C.muted).text(
        "Static analysis can only evidence technical controls. Controls marked “not assessable” require process, physical or organizational evidence and are out of scope for this report.",
        x0, y, { width: w },
      );
      y = doc.y + 6;

      // Per framework
      for (const r of input.reports) {
        doc.addPage();
        y = 50;
        const st = frameworkStats(r);
        section(`${r.framework.toUpperCase()}${r.version ? `  ·  ${r.version}` : ""}`);
        doc.fontSize(8).fillColor(C.muted).text(
          `${SOURCE_LABELS[r.mappingSource || ""] || r.mappingSource || ""} · ${r.totalControls} controls`,
          x0, y, { width: w },
        );
        y = doc.y + 8;

        const cards = [
          { n: String(st.gaps), l: "CONTROLS WITH GAPS", c: C.critical },
          { n: String(st.clear), l: "NO ISSUES DETECTED", c: C.green },
          { n: String(st.notCovered), l: "NOT ASSESSABLE", c: C.muted },
          { n: st.passRate == null ? "—" : `${st.passRate}%`, l: "ASSESSABLE CLEAR", c: C.text },
        ];
        const cardW = (w - 30) / 4;
        cards.forEach((k, i) => {
          const cx = x0 + i * (cardW + 10);
          doc.roundedRect(cx, y, cardW, 50, 6).fillAndStroke(C.white, C.border);
          doc.fontSize(18).fillColor(k.c).text(k.n, cx, y + 8, { width: cardW, align: "center" });
          doc.fontSize(6.5).fillColor(C.muted).text(k.l, cx, y + 34, { width: cardW, align: "center" });
        });
        y += 62;

        subheading("Control gaps");
        const gaps = r.buckets?.gapsFound ?? [];
        if (gaps.length === 0) {
          doc.fontSize(8.5).fillColor(C.muted).text("No control gaps were found for this framework.", x0, y, { width: w });
          y = doc.y + 10;
        } else {
          table(
            ["CONTROL", "TITLE", "THEME", "FINDINGS", "CRIT/HIGH"],
            [70, w - 70 - 110 - 55 - 60, 110, 55, 60],
            gaps.map((g) => ({
              cells: [g.controlId, g.title, g.theme || "", String(g.findingCount), String(g.criticalHighCount)],
              colors: [undefined, undefined, C.secondary, undefined, g.criticalHighCount > 0 ? C.critical : undefined],
            })),
          );
        }

        const findings = mappedFindings(r);
        subheading(`Findings mapped to controls (${findings.length})`);
        if (findings.length === 0) {
          doc.fontSize(8.5).fillColor(C.muted).text("No findings were mapped to this framework's controls.", x0, y, { width: w });
          y = doc.y + 10;
        } else {
          table(
            ["FINDING", "SEVERITY", "CONTROLS"],
            [w - 65 - 190, 65, 190],
            findings.map((f) => ({
              cells: [
                `${f.title || f.id}${location(f) ? `\n${location(f)}` : ""}`,
                (f.severity || "INFO").toUpperCase(),
                f.controls.map((c) => `${c.controlId}${c.relevance ? ` (${c.relevance})` : ""}`).join("\n"),
              ],
              colors: [undefined, sevColor(f.severity), C.secondary],
            })),
          );
        }

        const clear = r.buckets?.noIssuesDetected ?? [];
        if (clear.length) {
          subheading("Controls with no issues detected");
          let bx = x0;
          for (const c of clear) {
            const bw = Math.min(w, c.controlId.length * 5 + 14);
            if (bx + bw > x0 + w) { bx = x0; y += 20; }
            ensure(20);
            doc.roundedRect(bx, y, bw, 16, 3).fillAndStroke(C.greenBg, C.border);
            doc.fontSize(7).fillColor(C.green).text(c.controlId, bx + 5, y + 4.5, { width: bw - 10, lineBreak: false });
            bx += bw + 6;
          }
          y += 28;
        }

        const notCovered = r.buckets?.notCovered ?? [];
        if (notCovered.length) {
          subheading("Requires evidence outside the codebase");
          table(
            ["CONTROL", "TITLE"],
            [70, w - 70],
            notCovered.map((c) => ({ cells: [c.controlId, c.title], colors: [C.secondary, C.secondary] })),
          );
        }
      }

      ensure(24);
      doc.fontSize(8).fillColor(C.muted).text(
        `Generated ${formatReportDate(new Date())} by Pepper · Confidential — for the authorized recipient only.`,
        x0, y + 6, { width: w, align: "center" },
      );

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}
