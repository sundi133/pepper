import { getCweCategory, getOwasp2024Code } from "@/scanners/sast/owasp-mapper";
import {
  escapeHtml,
  formatReportDate,
  loadPdfKit,
  renderReportShell,
  severityRank,
} from "./report-html";

// ─── Inputs ─────────────────────────────────────────────────────────
export type ExecutiveScan = {
  id: string;
  status: string;
  scanType: string;
  branch: string | null;
  commitSha: string | null;
  sourceType: string;
  sourceRef: string | null;
  gateResult: string;
  createdAt: Date;
  completedAt: Date | null;
  filesScanned: number;
  depsScanned: number;
  autoResolvedCount: number;
  project: { name: string; repoUrl: string | null } | null;
};

export type ExecutiveFinding = {
  id: string;
  scanner: string;
  severity: string;
  title: string;
  status?: string | null;
  cweId?: string | null;
  filePath?: string | null;
  riskScore?: number | null;
  isNew?: boolean | null;
  metadata?: unknown;
};

// ─── Summary model ──────────────────────────────────────────────────
export type PostureLevel = "CRITICAL" | "HIGH" | "MODERATE" | "LOW";

type SeverityCounts = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
};

type RoadmapBucket = { count: number; items: string[] };

export type ExecutiveSummary = {
  projectName: string;
  repoUrl: string | null;
  scanType: string;
  scanDate: Date;
  sourceLine: string;
  gateResult: string;
  filesScanned: number;
  depsScanned: number;
  posture: { level: PostureLevel; label: string; headline: string };
  active: SeverityCounts;
  statusCounts: {
    open: number;
    inProgress: number;
    resolved: number;
    falsePositive: number;
    acceptedRisk: number;
  };
  totalFindings: number;
  newFindings: number;
  autoResolved: number;
  riskAreas: { name: string; total: number; criticalHigh: number }[];
  topRisks: {
    title: string;
    severity: string;
    category: string;
    impact: string;
    isNew: boolean;
    /** How many open findings share this title (e.g. one secret in 5 files). */
    occurrences: number;
  }[];
  owasp: { code: string; name: string; count: number }[];
  roadmap: { now: RoadmapBucket; next: RoadmapBucket; later: RoadmapBucket };
  recommendations: string[];
};

const OWASP_2021: [string, string][] = [
  ["A01:2021", "Broken Access Control"],
  ["A02:2021", "Cryptographic Failures"],
  ["A03:2021", "Injection"],
  ["A04:2021", "Insecure Design"],
  ["A05:2021", "Security Misconfiguration"],
  ["A06:2021", "Vulnerable Components"],
  ["A07:2021", "Authentication Failures"],
  ["A08:2021", "Software & Data Integrity"],
  ["A09:2021", "Logging & Monitoring Failures"],
  ["A10:2021", "Server-Side Request Forgery"],
];

const ACTIVE_STATUSES = new Set(["OPEN", "IN_PROGRESS"]);

function isActive(f: ExecutiveFinding): boolean {
  return ACTIVE_STATUSES.has((f.status || "OPEN").toUpperCase());
}

export function findingCategory(f: Pick<ExecutiveFinding, "cweId" | "scanner">): string {
  const cat = getCweCategory(f.cweId);
  if (cat) return cat;
  const s = f.scanner.toUpperCase();
  if (s.includes("SECRET")) return "Secrets";
  if (s === "SCA" || s === "MALICIOUS_PKG") return "Dependencies";
  if (s === "IAC") return "IaC Misconfiguration";
  if (s === "CONTAINER") return "Container";
  if (s === "K8S") return "Kubernetes";
  return "Other";
}

function readReportField(metadata: unknown, key: string): string | undefined {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return undefined;
  const sections = (metadata as Record<string, unknown>).reportSections;
  if (!sections || typeof sections !== "object" || Array.isArray(sections)) return undefined;
  const v = (sections as Record<string, unknown>)[key];
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

function firstSentence(text: string, max = 220): string {
  const clean = text.replace(/\s+/g, " ").trim();
  const m = clean.match(/^(.+?[.!?])(\s|$)/);
  const s = m ? m[1] : clean;
  return s.length <= max ? s : s.slice(0, max - 1).trimEnd() + "…";
}

function countSeverities(findings: ExecutiveFinding[]): SeverityCounts {
  const c: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of findings) {
    const s = f.severity.toUpperCase();
    if (s === "CRITICAL") c.critical++;
    else if (s === "HIGH") c.high++;
    else if (s === "MEDIUM") c.medium++;
    else if (s === "LOW") c.low++;
    else c.info++;
    c.total++;
  }
  return c;
}

function roadmapBucket(findings: ExecutiveFinding[], severityLabel: string): RoadmapBucket {
  const byCat = new Map<string, number>();
  for (const f of findings) {
    const cat = findingCategory(f);
    byCat.set(cat, (byCat.get(cat) || 0) + 1);
  }
  const items = [...byCat.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([cat, n]) => `Resolve ${n} ${severityLabel} ${cat} issue${n === 1 ? "" : "s"}`);
  return { count: findings.length, items };
}

function postureFor(active: SeverityCounts): ExecutiveSummary["posture"] {
  if (active.critical > 0) {
    return {
      level: "CRITICAL",
      label: "Critical risk",
      headline: `${active.critical} critical and ${active.high} high severity issue${active.critical + active.high === 1 ? " remains" : "s remain"} open. Remediation should be prioritised before the next release.`,
    };
  }
  if (active.high > 0) {
    return {
      level: "HIGH",
      label: "High risk",
      headline: `No critical issues are open, but ${active.high} high severity issue${active.high === 1 ? " needs" : "s need"} remediation within the current release cycle.`,
    };
  }
  if (active.medium > 0) {
    return {
      level: "MODERATE",
      label: "Moderate risk",
      headline: `No critical or high severity issues are open. ${active.medium} medium severity issue${active.medium === 1 ? " should" : "s should"} be scheduled into upcoming work.`,
    };
  }
  return {
    level: "LOW",
    label: "Low risk",
    headline:
      active.total > 0
        ? `Only low or informational issues remain open (${active.total}). The application's security posture is healthy.`
        : "No open security issues were identified. The application's security posture is healthy.",
  };
}

function sourceLineFor(scan: ExecutiveScan): string {
  if (scan.sourceType === "SVN_CHECKOUT" && scan.sourceRef) return `SVN ${scan.sourceRef}`;
  if (scan.branch) {
    return `Branch ${scan.branch}${scan.commitSha ? ` · ${scan.commitSha.slice(0, 12)}` : ""}`;
  }
  return scan.sourceType;
}

export function buildExecutiveSummary(
  scan: ExecutiveScan,
  findings: ExecutiveFinding[],
): ExecutiveSummary {
  const activeFindings = findings.filter(isActive);
  const active = countSeverities(activeFindings);

  const statusCounts = { open: 0, inProgress: 0, resolved: 0, falsePositive: 0, acceptedRisk: 0 };
  for (const f of findings) {
    switch ((f.status || "OPEN").toUpperCase()) {
      case "IN_PROGRESS": statusCounts.inProgress++; break;
      case "RESOLVED": statusCounts.resolved++; break;
      case "FALSE_POSITIVE": statusCounts.falsePositive++; break;
      case "ACCEPTED_RISK": statusCounts.acceptedRisk++; break;
      default: statusCounts.open++;
    }
  }

  const areaMap = new Map<string, { total: number; criticalHigh: number }>();
  for (const f of activeFindings) {
    const cat = findingCategory(f);
    const cur = areaMap.get(cat) || { total: 0, criticalHigh: 0 };
    cur.total++;
    if (severityRank(f.severity) <= 1) cur.criticalHigh++;
    areaMap.set(cat, cur);
  }
  const riskAreas = [...areaMap.entries()]
    .map(([name, v]) => ({ name, ...v }))
    .sort((a, b) => b.criticalHigh - a.criticalHigh || b.total - a.total)
    .slice(0, 8);

  // Group repeats of the same issue (e.g. one secret committed in several
  // files) so the top risks list distinct problems. The sort puts the most
  // severe instance first, so it represents its group.
  const riskGroups = new Map<string, ExecutiveSummary["topRisks"][number]>();
  const ranked = [...activeFindings]
    .filter((f) => severityRank(f.severity) <= 2)
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        (b.riskScore ?? 0) - (a.riskScore ?? 0),
    );
  for (const f of ranked) {
    const title = readReportField(f.metadata, "vulnerabilityName") || f.title;
    const key = title.trim().toLowerCase();
    const existing = riskGroups.get(key);
    if (existing) {
      existing.occurrences++;
      existing.isNew ||= f.isNew === true;
      continue;
    }
    const impact = readReportField(f.metadata, "impact");
    riskGroups.set(key, {
      title,
      severity: f.severity.toUpperCase(),
      category: findingCategory(f),
      impact: impact ? firstSentence(impact) : "",
      isNew: f.isNew === true,
      occurrences: 1,
    });
  }
  const topRisks = [...riskGroups.values()].slice(0, 5);

  const owaspCounts = new Map<string, number>();
  for (const f of activeFindings) {
    const code = getOwasp2024Code(f.cweId);
    if (code) owaspCounts.set(code, (owaspCounts.get(code) || 0) + 1);
  }
  const owasp = OWASP_2021.map(([code, name]) => ({ code, name, count: owaspCounts.get(code) || 0 }));

  const critHigh = activeFindings.filter((f) => severityRank(f.severity) <= 1);
  const medium = activeFindings.filter((f) => severityRank(f.severity) === 2);
  const lowInfo = activeFindings.filter((f) => severityRank(f.severity) >= 3);
  const roadmap = {
    now: roadmapBucket(critHigh, "critical/high"),
    next: roadmapBucket(medium, "medium"),
    later: roadmapBucket(lowInfo, "low"),
  };

  const newFindings = findings.filter((f) => f.isNew === true).length;
  const areaNames = new Set(areaMap.keys());
  const recommendations: string[] = [];
  if (active.critical > 0) {
    recommendations.push(
      `Treat the ${active.critical} open critical finding${active.critical === 1 ? "" : "s"} as release blockers and remediate within 7 days.`,
    );
  }
  if (active.high > 0) {
    recommendations.push(
      `Assign owners to the ${active.high} high severity finding${active.high === 1 ? "" : "s"} and target remediation within 30 days.`,
    );
  }
  if (areaNames.has("Secrets")) {
    recommendations.push(
      "Rotate any exposed credentials immediately and move secrets into a managed vault.",
    );
  }
  if (areaNames.has("Dependencies")) {
    recommendations.push(
      "Upgrade vulnerable third-party dependencies and enable automated dependency update PRs.",
    );
  }
  if (scan.gateResult === "FAILED") {
    recommendations.push(
      "The build gate failed for this scan; keep the gate enforced so new high-risk issues cannot reach production.",
    );
  }
  if (newFindings > 0) {
    recommendations.push(
      `${newFindings} issue${newFindings === 1 ? " was" : "s were"} introduced since the previous scan; enable pull-request scanning to catch regressions earlier.`,
    );
  }
  if (statusCounts.acceptedRisk > 0) {
    recommendations.push(
      `Review the ${statusCounts.acceptedRisk} accepted risk${statusCounts.acceptedRisk === 1 ? "" : "s"} each quarter to confirm they are still acceptable.`,
    );
  }
  if (recommendations.length === 0) {
    recommendations.push(
      "Maintain the current posture with scheduled scans and pull-request scanning on every change.",
    );
  }

  return {
    projectName: scan.project?.name || "Scan",
    repoUrl: scan.project?.repoUrl?.trim() || null,
    scanType: scan.scanType,
    scanDate: scan.completedAt ?? scan.createdAt,
    sourceLine: sourceLineFor(scan),
    gateResult: scan.gateResult,
    filesScanned: scan.filesScanned,
    depsScanned: scan.depsScanned,
    posture: postureFor(active),
    active,
    statusCounts,
    totalFindings: findings.length,
    newFindings,
    autoResolved: scan.autoResolvedCount,
    riskAreas,
    topRisks,
    owasp,
    roadmap,
    recommendations,
  };
}

// ─── HTML ───────────────────────────────────────────────────────────
function sevClass(sev: string): string {
  const s = sev.toLowerCase();
  return ["critical", "high", "medium", "low"].includes(s) ? `sev-${s}` : "sev-info";
}

function postureClass(level: PostureLevel): string {
  return {
    CRITICAL: "solid-critical",
    HIGH: "solid-high",
    MODERATE: "solid-medium",
    LOW: "solid-low",
  }[level];
}

export function buildExecutiveHtml(summary: ExecutiveSummary): string {
  const s = summary;
  const maxAreaTotal = Math.max(1, ...s.riskAreas.map((a) => a.total));

  const kpis = [
    { n: s.active.critical, l: "Open critical", c: "#dc2626" },
    { n: s.active.high, l: "Open high", c: "#ea580c" },
    { n: s.active.medium, l: "Open medium", c: "#d97706" },
    { n: s.active.low + s.active.info, l: "Open low / info", c: "#2563eb" },
    { n: s.statusCounts.resolved, l: "Resolved", c: "#059669" },
  ]
    .map(
      (k) =>
        `<div class="card"><div class="n" style="color:${k.c}">${k.n}</div><div class="l">${escapeHtml(k.l)}</div></div>`,
    )
    .join("");

  const areas =
    s.riskAreas.length === 0
      ? `<p class="muted">No open issues in any risk area.</p>`
      : s.riskAreas
          .map(
            (a) => `<div class="bar-row">
          <div>${escapeHtml(a.name)}${a.criticalHigh > 0 ? ` <span class="muted">(${a.criticalHigh} crit/high)</span>` : ""}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${Math.max(4, Math.round((a.total / maxAreaTotal) * 100))}%"></div></div>
          <div class="v">${a.total}</div>
        </div>`,
          )
          .join("");

  const topRisks =
    s.topRisks.length === 0
      ? `<p class="muted">No open critical, high or medium severity issues.</p>`
      : `<table>
        <thead><tr><th style="width:32px">#</th><th>Risk</th><th style="width:150px">Area</th><th style="width:100px">Severity</th></tr></thead>
        <tbody>${s.topRisks
          .map(
            (r, i) => `<tr>
            <td>${i + 1}</td>
            <td><strong>${escapeHtml(r.title)}</strong>${r.occurrences > 1 ? ` <span class="muted">× ${r.occurrences}</span>` : ""}${r.isNew ? ` <span class="pill sev-info">New</span>` : ""}${r.impact ? `<div class="muted">${escapeHtml(r.impact)}</div>` : ""}</td>
            <td>${escapeHtml(r.category)}</td>
            <td><span class="pill ${sevClass(r.severity)}">${escapeHtml(r.severity)}</span></td>
          </tr>`,
          )
          .join("")}</tbody>
      </table>`;

  const owasp = `<div class="chips">${s.owasp
    .map(
      (o) =>
        `<span class="chip ${o.count > 0 ? "sev-medium" : "ok"}" title="${escapeHtml(o.name)}"><strong>${escapeHtml(o.code)}</strong> ${escapeHtml(o.name)} · ${o.count > 0 ? o.count : "clear"}</span>`,
    )
    .join("")}</div>`;

  const roadmapCol = (title: string, color: string, b: RoadmapBucket) => `<div class="col">
      <h4 style="color:${color}">${escapeHtml(title)} · ${b.count}</h4>
      ${
        b.items.length
          ? `<ul class="tight">${b.items.map((i) => `<li>${escapeHtml(i)}</li>`).join("")}</ul>`
          : `<p class="muted">Nothing scheduled</p>`
      }
    </div>`;

  const body = `
    <h2>Security posture</h2>
    <div class="callout">
      <span class="pill ${postureClass(s.posture.level)}">${escapeHtml(s.posture.label)}</span>
      <div style="flex:1 1 320px">${escapeHtml(s.posture.headline)}</div>
    </div>
    <div class="cards">${kpis}</div>
    <p class="muted">
      ${s.totalFindings} total findings · ${s.statusCounts.open} open · ${s.statusCounts.inProgress} in progress ·
      ${s.statusCounts.resolved} resolved · ${s.statusCounts.acceptedRisk} accepted risk · ${s.statusCounts.falsePositive} false positive.
      ${s.newFindings > 0 ? ` ${s.newFindings} new since the previous scan.` : ""}
      ${s.autoResolved > 0 ? ` ${s.autoResolved} fixed since the previous scan.` : ""}
    </p>

    <h2>Key recommendations</h2>
    <ul class="tight">${s.recommendations.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>

    <h2>Top business risks</h2>
    ${topRisks}

    <h2>Risk areas</h2>
    ${areas}

    <h2>OWASP Top 10 exposure</h2>
    ${owasp}

    <h2>Remediation roadmap</h2>
    <div class="grid3">
      ${roadmapCol("Now · 0–30 days", "#dc2626", s.roadmap.now)}
      ${roadmapCol("Next · 30–90 days", "#d97706", s.roadmap.next)}
      ${roadmapCol("Later · 90+ days", "#6b7280", s.roadmap.later)}
    </div>

    <h2>Scope</h2>
    <p class="muted">${s.filesScanned} files and ${s.depsScanned} dependencies scanned · ${escapeHtml(s.scanType)} scan · ${escapeHtml(s.sourceLine)} · Build gate ${escapeHtml(s.gateResult)}.</p>
  `;

  return renderReportShell({
    title: `Executive Security Summary — ${s.projectName}`,
    eyebrow: "Confidential · Executive summary",
    heading: "Executive Security Summary",
    subtitle: `${escapeHtml(s.projectName)} · ${escapeHtml(formatReportDate(s.scanDate))}${s.repoUrl ? `<br>${escapeHtml(s.repoUrl)}` : ""}`,
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
  mediumBg: "#fef3c7",
  bar: "#6ea8d9",
};

function sevPdfColor(sev: string): string {
  switch (sev) {
    case "CRITICAL": return C.critical;
    case "HIGH": return C.high;
    case "MEDIUM": return C.medium;
    case "LOW": return C.low;
    default: return C.muted;
  }
}

function posturePdfColor(level: PostureLevel): string {
  return { CRITICAL: C.critical, HIGH: C.high, MODERATE: C.medium, LOW: C.green }[level];
}

export function buildExecutivePdf(summary: ExecutiveSummary): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
      const PDFDocument = loadPdfKit();
      const s = summary;
      const chunks: Buffer[] = [];
      const doc = new PDFDocument({
        size: "A4",
        margins: { top: 50, bottom: 50, left: 50, right: 50 },
        info: {
          Title: `Executive Security Summary — ${s.projectName}`,
          Author: "Pepper SAST",
          Subject: "Executive Security Summary",
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
        doc.fontSize(10).fillColor(C.text).text(title, x0 + 12, y + 2);
        y += 26;
      };

      // Header band
      doc.rect(0, 0, pageW, 120).fill(C.header);
      doc.fontSize(9).fillColor("#94a3b8").text("CONFIDENTIAL  ·  EXECUTIVE SUMMARY", x0, 28, { width: w });
      doc.fontSize(24).fillColor(C.white).text("Executive Security Summary", x0, 48, { width: w });
      doc.fontSize(10).fillColor("#cbd5e1")
        .text(`${s.projectName} · ${formatReportDate(s.scanDate)}`, x0, 84, { width: w });
      if (s.repoUrl) {
        doc.fontSize(8).fillColor("#94a3b8").text(s.repoUrl, x0, 100, { width: w, lineBreak: false, ellipsis: true });
      }
      y = 140;

      // Posture
      section("SECURITY POSTURE");
      doc.fontSize(9);
      const headlineH = doc.heightOfString(s.posture.headline, { width: w - 160 });
      const boxH = Math.max(46, headlineH + 20);
      doc.roundedRect(x0, y, w, boxH, 6).fillAndStroke(C.light, C.border);
      const pLabel = s.posture.label.toUpperCase();
      doc.roundedRect(x0 + 12, y + boxH / 2 - 11, 120, 22, 4).fill(posturePdfColor(s.posture.level));
      doc.fontSize(9).fillColor(C.white).text(pLabel, x0 + 12, y + boxH / 2 - 6, { width: 120, align: "center" });
      doc.fontSize(9).fillColor(C.text).text(s.posture.headline, x0 + 145, y + (boxH - headlineH) / 2, { width: w - 160 });
      y += boxH + 12;

      const kpis = [
        { n: s.active.critical, l: "OPEN CRITICAL", c: C.critical },
        { n: s.active.high, l: "OPEN HIGH", c: C.high },
        { n: s.active.medium, l: "OPEN MEDIUM", c: C.medium },
        { n: s.active.low + s.active.info, l: "OPEN LOW / INFO", c: C.low },
        { n: s.statusCounts.resolved, l: "RESOLVED", c: C.green },
      ];
      const cardW = (w - 40) / 5;
      kpis.forEach((k, i) => {
        const cx = x0 + i * (cardW + 10);
        doc.roundedRect(cx, y, cardW, 52, 6).fillAndStroke(C.white, C.border);
        doc.fontSize(20).fillColor(k.c).text(String(k.n), cx, y + 8, { width: cardW, align: "center" });
        doc.fontSize(6.5).fillColor(C.muted).text(k.l, cx, y + 36, { width: cardW, align: "center" });
      });
      y += 62;

      const statusLine =
        `${s.totalFindings} total findings · ${s.statusCounts.open} open · ${s.statusCounts.inProgress} in progress · ` +
        `${s.statusCounts.resolved} resolved · ${s.statusCounts.acceptedRisk} accepted risk · ${s.statusCounts.falsePositive} false positive` +
        (s.newFindings > 0 ? ` · ${s.newFindings} new since previous scan` : "") +
        (s.autoResolved > 0 ? ` · ${s.autoResolved} fixed since previous scan` : "");
      doc.fontSize(8).fillColor(C.muted).text(statusLine, x0, y, { width: w });
      y = doc.y + 6;

      // Recommendations
      section("KEY RECOMMENDATIONS");
      for (const r of s.recommendations) {
        doc.fontSize(9);
        const h = doc.heightOfString(`•  ${r}`, { width: w });
        ensure(h + 4);
        doc.fillColor(C.secondary).text(`•  ${r}`, x0, y, { width: w });
        y = doc.y + 4;
      }

      // Top risks
      section("TOP BUSINESS RISKS", 80);
      if (s.topRisks.length === 0) {
        doc.fontSize(9).fillColor(C.muted).text("No open critical, high or medium severity issues.", x0, y, { width: w });
        y = doc.y + 6;
      } else {
        const cols = [24, w - 24 - 120 - 70, 120, 70];
        const cx = [x0, x0 + cols[0], x0 + cols[0] + cols[1], x0 + cols[0] + cols[1] + cols[2]];
        doc.rect(x0, y, w, 18).fill(C.header);
        doc.fontSize(7).fillColor(C.white);
        ["#", "RISK", "AREA", "SEVERITY"].forEach((h, i) => doc.text(h, cx[i] + 5, y + 6, { width: cols[i] - 10 }));
        y += 18;
        s.topRisks.forEach((r, idx) => {
          const title = r.occurrences > 1 ? `${r.title}  (×${r.occurrences})` : r.title;
          doc.fontSize(8.5);
          const titleH = doc.heightOfString(title, { width: cols[1] - 10 });
          doc.fontSize(7.5);
          const impactH = r.impact ? doc.heightOfString(r.impact, { width: cols[1] - 10 }) + 3 : 0;
          const rowH = Math.max(22, titleH + impactH + 12);
          ensure(rowH);
          doc.rect(x0, y, w, rowH).fill(idx % 2 === 0 ? C.white : C.light);
          doc.fontSize(8.5).fillColor(C.text).text(String(idx + 1), cx[0] + 5, y + 6, { width: cols[0] - 10 });
          doc.text(title, cx[1] + 5, y + 6, { width: cols[1] - 10 });
          if (r.impact) {
            doc.fontSize(7.5).fillColor(C.muted).text(r.impact, cx[1] + 5, y + 6 + titleH + 3, { width: cols[1] - 10 });
          }
          doc.fontSize(8).fillColor(C.text).text(r.category, cx[2] + 5, y + 6, { width: cols[2] - 10 });
          const bw = Math.min(cols[3] - 10, r.severity.length * 6 + 12);
          doc.roundedRect(cx[3] + 5, y + 4, bw, 14, 3).fill(sevPdfColor(r.severity));
          doc.fontSize(7).fillColor(C.white).text(r.severity, cx[3] + 5, y + 7.5, { width: bw, align: "center" });
          y += rowH;
        });
        y += 6;
      }

      // Risk areas
      section("RISK AREAS");
      if (s.riskAreas.length === 0) {
        doc.fontSize(9).fillColor(C.muted).text("No open issues in any risk area.", x0, y, { width: w });
        y = doc.y + 6;
      } else {
        const maxA = Math.max(...s.riskAreas.map((a) => a.total), 1);
        const labelW = 130;
        for (const a of s.riskAreas) {
          ensure(22);
          doc.fontSize(8.5).fillColor(C.text).text(a.name, x0, y + 3, { width: labelW, align: "right", lineBreak: false, ellipsis: true });
          const barMax = w - labelW - 100;
          const bw = Math.max(8, (a.total / maxA) * barMax);
          doc.roundedRect(x0 + labelW + 10, y, bw, 15, 3).fill(C.bar);
          const suffix = a.criticalHigh > 0 ? `  (${a.criticalHigh} crit/high)` : "";
          doc.fontSize(8.5).fillColor(C.text).text(`${a.total}${suffix}`, x0 + labelW + 16 + bw, y + 3, { lineBreak: false });
          y += 21;
        }
        y += 4;
      }

      // OWASP
      section("OWASP TOP 10 EXPOSURE");
      let bx = x0;
      for (const o of s.owasp) {
        const label = `${o.code} · ${o.count > 0 ? o.count : "clear"}`;
        const bw = label.length * 5.3 + 16;
        if (bx + bw > x0 + w) { bx = x0; y += 22; }
        ensure(22);
        doc.roundedRect(bx, y, bw, 18, 4).fillAndStroke(o.count > 0 ? C.mediumBg : C.greenBg, C.border);
        doc.fontSize(7).fillColor(o.count > 0 ? C.medium : C.green).text(label, bx + 6, y + 5.5, { width: bw - 12, lineBreak: false });
        bx += bw + 8;
      }
      y += 30;

      // Roadmap
      section("REMEDIATION ROADMAP", 90);
      const colW = (w - 20) / 3;
      const cols3: [string, string, RoadmapBucket][] = [
        ["NOW · 0–30 DAYS", C.critical, s.roadmap.now],
        ["NEXT · 30–90 DAYS", C.medium, s.roadmap.next],
        ["LATER · 90+ DAYS", C.muted, s.roadmap.later],
      ];
      const startY = y;
      let maxY = y;
      cols3.forEach(([title, color, b], i) => {
        const cx = x0 + i * (colW + 10);
        doc.roundedRect(cx, startY, colW, 18, 3).fill(C.light);
        doc.fontSize(8).fillColor(color).text(`${title} · ${b.count}`, cx + 8, startY + 5, { width: colW - 16 });
        let cy = startY + 24;
        const items = b.items.length ? b.items : ["Nothing scheduled"];
        for (const item of items) {
          doc.fontSize(8).fillColor(b.items.length ? C.secondary : C.muted)
            .text(`•  ${item}`, cx + 6, cy, { width: colW - 12 });
          cy = doc.y + 3;
        }
        maxY = Math.max(maxY, cy);
      });
      y = maxY + 8;

      // Scope
      section("SCOPE", 30);
      doc.fontSize(8.5).fillColor(C.secondary).text(
        `${s.filesScanned} files and ${s.depsScanned} dependencies scanned · ${s.scanType} scan · ${s.sourceLine} · Build gate ${s.gateResult}.`,
        x0, y, { width: w },
      );
      y = doc.y + 16;
      ensure(20);
      doc.fontSize(8).fillColor(C.muted).text(
        `Generated ${formatReportDate(new Date())} by Pepper · Confidential — for the authorized recipient only.`,
        x0, y, { width: w, align: "center" },
      );

      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}
