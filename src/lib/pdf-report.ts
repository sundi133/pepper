import { SCANNER_LABELS } from "./constants";

// ─── Types ──────────────────────────────────────────────────────────
type ScanData = {
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
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  project: { name: string; repoUrl: string | null } | null;
};

type FindingData = {
  id: string;
  scanner: string;
  severity: string;
  title: string;
  description: string;
  status?: string | null;
  filePath?: string | null;
  startLine?: number | null;
  endLine?: number | null;
  snippet?: string | null;
  ruleId?: string | null;
  cweId?: string | null;
  cveId?: string | null;
  confidence?: number | null;
  metadata?: unknown;
};

type StoredReport = {
  vulnerabilityName: string;
  summary: string;
  stepsToReproduce: string[];
  impact: string;
  remediation: string[];
};

// ─── Colors ─────────────────────────────────────────────────────────
const COLORS = {
  darkBlue: "#1a2332" as const,
  headerBg: "#1e3a5f" as const,
  sectionBar: "#1e3a5f" as const,
  textPrimary: "#1a1a2e" as const,
  textSecondary: "#4b5563" as const,
  textMuted: "#6b7280" as const,
  border: "#e5e7eb" as const,
  pageBg: "#ffffff" as const,
  critical: "#dc2626" as const,
  criticalBg: "#fee2e2" as const,
  high: "#ea580c" as const,
  highBg: "#ffedd5" as const,
  medium: "#d97706" as const,
  mediumBg: "#fef3c7" as const,
  low: "#2563eb" as const,
  lowBg: "#dbeafe" as const,
  info: "#6b7280" as const,
  infoBg: "#f3f4f6" as const,
  white: "#ffffff" as const,
  lightGray: "#f9fafb" as const,
  impactBg: "#fff7ed" as const,
  impactBorder: "#fed7aa" as const,
  pocBg: "#1e293b" as const,
  pocText: "#e2e8f0" as const,
  remedBg: "#fefce8" as const,
  remedBorder: "#fde68a" as const,
  badgeBg: "#f0f4f8" as const,
  badgeBorder: "#cbd5e1" as const,
  green: "#059669" as const,
  greenBg: "#d1fae5" as const,
};

function severityColor(sev: string): string {
  switch (sev.toUpperCase()) {
    case "CRITICAL": return COLORS.critical;
    case "HIGH": return COLORS.high;
    case "MEDIUM": return COLORS.medium;
    case "LOW": return COLORS.low;
    default: return COLORS.info;
  }
}

function severityBgColor(sev: string): string {
  switch (sev.toUpperCase()) {
    case "CRITICAL": return COLORS.criticalBg;
    case "HIGH": return COLORS.highBg;
    case "MEDIUM": return COLORS.mediumBg;
    case "LOW": return COLORS.lowBg;
    default: return COLORS.infoBg;
  }
}

// ─── CWE → Category mapping ────────────────────────────────────────
const CWE_CATEGORY_MAP: Record<string, string> = {
  "CWE-79": "XSS",
  "CWE-80": "XSS",
  "CWE-87": "XSS",
  "CWE-89": "Injection",
  "CWE-90": "Injection",
  "CWE-91": "Injection",
  "CWE-94": "Injection",
  "CWE-95": "Injection",
  "CWE-78": "Injection",
  "CWE-77": "Injection",
  "CWE-76": "Injection",
  "CWE-917": "Injection",
  "CWE-22": "Path Traversal",
  "CWE-23": "Path Traversal",
  "CWE-36": "Path Traversal",
  "CWE-73": "Path Traversal",
  "CWE-200": "Info Disclosure",
  "CWE-209": "Info Disclosure",
  "CWE-532": "Info Disclosure",
  "CWE-312": "Secrets",
  "CWE-321": "Secrets",
  "CWE-798": "Secrets",
  "CWE-259": "Secrets",
  "CWE-287": "Authentication",
  "CWE-306": "Authentication",
  "CWE-307": "Authentication",
  "CWE-862": "Authorization",
  "CWE-863": "Authorization",
  "CWE-639": "Authorization",
  "CWE-284": "Authorization",
  "CWE-352": "CSRF",
  "CWE-918": "SSRF",
  "CWE-611": "XXE",
  "CWE-502": "Deserialization",
  "CWE-327": "Cryptography",
  "CWE-328": "Cryptography",
  "CWE-330": "Cryptography",
  "CWE-916": "Cryptography",
  "CWE-1321": "Prototype Pollution",
  "CWE-400": "DoS",
  "CWE-770": "DoS",
  "CWE-1333": "ReDoS",
};

// CWE → OWASP Top 10 2021
const CWE_OWASP_MAP: Record<string, string> = {
  "CWE-89": "A03:2021", "CWE-78": "A03:2021", "CWE-77": "A03:2021",
  "CWE-94": "A03:2021", "CWE-917": "A03:2021",
  "CWE-79": "A03:2021", "CWE-80": "A03:2021",
  "CWE-22": "A01:2021", "CWE-862": "A01:2021", "CWE-863": "A01:2021",
  "CWE-639": "A01:2021", "CWE-284": "A01:2021",
  "CWE-287": "A07:2021", "CWE-306": "A07:2021", "CWE-307": "A07:2021",
  "CWE-327": "A02:2021", "CWE-328": "A02:2021", "CWE-916": "A02:2021",
  "CWE-798": "A07:2021", "CWE-312": "A02:2021",
  "CWE-611": "A05:2021", "CWE-918": "A10:2021",
  "CWE-502": "A08:2021", "CWE-200": "A01:2021",
  "CWE-352": "A01:2021",
};

function findingCategory(f: FindingData): string {
  if (f.cweId && CWE_CATEGORY_MAP[f.cweId]) return CWE_CATEGORY_MAP[f.cweId];
  const s = f.scanner.toUpperCase();
  if (s.includes("SECRET")) return "Secrets";
  if (s === "SCA" || s === "MALICIOUS_PKG") return "Dependencies";
  if (s === "IAC") return "IaC Misconfiguration";
  if (s === "CONTAINER") return "Container";
  if (s === "DAST") return "DAST";
  return "Other";
}

function findingOwasp(f: FindingData): string | null {
  if (f.cweId && CWE_OWASP_MAP[f.cweId]) return CWE_OWASP_MAP[f.cweId];
  return null;
}

function scannerLabel(scanner: string): string {
  return SCANNER_LABELS[scanner as keyof typeof SCANNER_LABELS] || scanner;
}

function formatDate(date: Date): string {
  return new Intl.DateTimeFormat("en", { dateStyle: "long" }).format(date);
}

function readReport(metadata: unknown): StoredReport | undefined {
  const data = metadata && typeof metadata === "object" && !Array.isArray(metadata)
    ? (metadata as Record<string, unknown>)
    : {};
  const value = data.reportSections;
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const r = value as Record<string, unknown>;
  if (typeof r.vulnerabilityName !== "string" || typeof r.summary !== "string") return undefined;
  return {
    vulnerabilityName: r.vulnerabilityName,
    summary: r.summary,
    stepsToReproduce: Array.isArray(r.stepsToReproduce)
      ? r.stepsToReproduce.filter((s): s is string => typeof s === "string")
      : [],
    impact: typeof r.impact === "string" ? r.impact : "",
    remediation: Array.isArray(r.remediation)
      ? r.remediation.filter((s): s is string => typeof s === "string")
      : [],
  };
}

function getMetaField(metadata: unknown, key: string): string | undefined {
  if (!metadata || typeof metadata !== "object") return undefined;
  const v = (metadata as Record<string, unknown>)[key];
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.substring(0, max - 3) + "...";
}

function riskLevel(criticalCount: number, highCount: number): { label: string; color: string; bg: string } {
  if (criticalCount > 0) return { label: "CRITICAL RISK", color: COLORS.white, bg: COLORS.critical };
  if (highCount > 0) return { label: "HIGH RISK", color: COLORS.white, bg: COLORS.high };
  return { label: "MODERATE RISK", color: COLORS.white, bg: COLORS.medium };
}

// ─── PDF Builder ────────────────────────────────────────────────────

export function buildPdfReport(scan: ScanData, findings: FindingData[]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    try {
    // Dynamic require to avoid webpack bundling pdfkit's fs-dependent font loading
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const PDFDocument: new (options?: PDFKit.PDFDocumentOptions) => PDFKit.PDFDocument = require("pdfkit");
    const chunks: Buffer[] = [];
    const doc = new PDFDocument({
      size: "A4",
      margins: { top: 50, bottom: 50, left: 50, right: 50 },
      bufferPages: true,
      info: {
        Title: `Security Assessment Report — ${scan.project?.name || "Scan"}`,
        Author: "Pepper SAST",
        Subject: "Security Assessment",
      },
    });

    doc.on("data", (chunk: Buffer) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    // A4 = 595.28 x 841.89
    const pageW = 595.28;
    const marginL = 50;
    const marginR = 50;
    const contentW = pageW - marginL - marginR;
    const projectName = scan.project?.name || "Scan";
    const totalFindings = scan.criticalCount + scan.highCount + scan.mediumCount + scan.lowCount + scan.infoCount;
    const risk = riskLevel(scan.criticalCount, scan.highCount);

    // ════════════════════════════════════════════════════════════════
    // PAGE 1: HEADER
    // ════════════════════════════════════════════════════════════════
    doc.rect(0, 0, pageW, 130).fill(COLORS.headerBg);

    doc.fontSize(9).fillColor("#94a3b8")
      .text("CONFIDENTIAL  \u00B7  SECURITY ASSESSMENT", marginL, 30, { width: contentW });

    doc.fontSize(26).fillColor(COLORS.white)
      .text("Security Assessment Report", marginL, 55, { width: contentW });

    const scanDate = scan.completedAt ? formatDate(scan.completedAt) : formatDate(scan.createdAt);
    const subtitle = `${projectName} \u00B7 ${scan.scanType} Scan \u00B7 ${scanDate}`;
    doc.fontSize(10).fillColor("#94a3b8")
      .text(subtitle, marginL, 95, { width: contentW });
    if (scan.project?.repoUrl) {
      doc.fontSize(9).fillColor("#cbd5e1")
        .text(truncate(scan.project.repoUrl, 80), marginL, 112, { width: contentW });
    }

    // ════════════════════════════════════════════════════════════════
    // EXECUTIVE BRIEF
    // ════════════════════════════════════════════════════════════════
    let y = 155;
    y = drawSectionHeader(doc, "EXECUTIVE BRIEF", marginL, y, contentW);
    y += 10;

    // Risk badge + summary text
    doc.roundedRect(marginL, y, contentW, 50, 6)
      .fillAndStroke(COLORS.lightGray, COLORS.border);

    // Risk badge
    const badgeW = risk.label.length * 7 + 24;
    doc.roundedRect(marginL + 15, y + 13, badgeW, 24, 4).fill(risk.bg);
    doc.fontSize(10).fillColor(risk.color)
      .text(risk.label, marginL + 15 + 8, y + 18, { width: badgeW - 16 });

    // Summary text
    const briefText = `The assessment identified ${scan.criticalCount} critical and ${scan.highCount} high severity findings across ${totalFindings} total issues. ${scan.criticalCount > 0 ? "Prioritized remediation is advised before the next release." : "Review recommended before deployment."}`;
    doc.fontSize(9).fillColor(COLORS.textPrimary)
      .text(briefText, marginL + badgeW + 30, y + 14, { width: contentW - badgeW - 50 });

    y += 65;

    // Severity summary cards
    const cardW = (contentW - 40) / 5;
    const cards = [
      { count: totalFindings, label: "FINDINGS", color: COLORS.textPrimary },
      { count: scan.criticalCount, label: "CRITICAL", color: COLORS.critical },
      { count: scan.highCount, label: "HIGH", color: COLORS.high },
      { count: scan.mediumCount, label: "MEDIUM", color: COLORS.medium },
      { count: scan.lowCount, label: "LOW", color: COLORS.low },
    ];

    cards.forEach((card, i) => {
      const cx = marginL + i * (cardW + 10);
      doc.roundedRect(cx, y, cardW, 55, 6).fillAndStroke(COLORS.white, COLORS.border);
      doc.fontSize(22).fillColor(card.color)
        .text(String(card.count), cx, y + 8, { width: cardW, align: "center" });
      doc.fontSize(7).fillColor(COLORS.textMuted)
        .text(card.label, cx, y + 38, { width: cardW, align: "center" });
    });
    y += 75;

    // ════════════════════════════════════════════════════════════════
    // FINDINGS BY CATEGORY
    // ════════════════════════════════════════════════════════════════
    y = drawSectionHeader(doc, "FINDINGS BY CATEGORY", marginL, y, contentW);
    y += 10;

    const catCounts = new Map<string, number>();
    for (const f of findings) {
      const cat = findingCategory(f);
      catCounts.set(cat, (catCounts.get(cat) || 0) + 1);
    }
    const sortedCats = [...catCounts.entries()].sort((a, b) => b[1] - a[1]);
    const maxCatCount = sortedCats[0]?.[1] || 1;

    for (const [cat, count] of sortedCats.slice(0, 8)) {
      const labelW = 100;
      doc.fontSize(9).fillColor(COLORS.textPrimary)
        .text(cat, marginL, y + 2, { width: labelW, align: "right" });

      const barMaxW = contentW - labelW - 50;
      const barW = Math.max(20, (count / maxCatCount) * barMaxW);
      doc.roundedRect(marginL + labelW + 10, y, barW, 16, 3).fill("#6ea8d9");

      doc.fontSize(9).fillColor(COLORS.textPrimary)
        .text(String(count), marginL + labelW + barW + 15, y + 2);
      y += 22;
    }
    y += 10;

    // ════════════════════════════════════════════════════════════════
    // TOP FINDINGS TABLE
    // ════════════════════════════════════════════════════════════════
    if (y > 580) { doc.addPage(); y = 50; }
    y = drawSectionHeader(doc, "TOP FINDINGS", marginL, y, contentW);
    y += 10;

    // Sort by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    const severityOrder: Record<string, number> = {
      CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
    };
    const sortedFindings = [...findings].sort((a, b) => {
      const aOrder = severityOrder[a.severity.toUpperCase()] ?? 999;
      const bOrder = severityOrder[b.severity.toUpperCase()] ?? 999;
      return aOrder - bOrder;
    });

    // Table header
    const cols = [30, 110, 85, 65, 65, 65];
    const colX = [marginL];
    for (let i = 1; i < cols.length; i++) colX.push(colX[i - 1] + cols[i - 1]);

    doc.rect(marginL, y, contentW, 20).fill(COLORS.headerBg);
    doc.fontSize(7).fillColor(COLORS.white);
    ["#", "FINDING", "CATEGORY", "SEVERITY", "OWASP", "STATUS"]
      .forEach((h, i) => doc.text(h, colX[i] + 4, y + 6, { width: cols[i] - 8 }));
    y += 20;

    // Table rows (top 20 sorted)
    const topFindings = sortedFindings.slice(0, 20);
    for (let idx = 0; idx < topFindings.length; idx++) {
      if (y > 750) { doc.addPage(); y = 50; }
      const f = topFindings[idx];
      const rowBg = idx % 2 === 0 ? COLORS.white : COLORS.lightGray;
      doc.rect(marginL, y, contentW, 20).fill(rowBg);

      doc.fontSize(8).fillColor(COLORS.textPrimary);
      doc.text(String(idx + 1), colX[0] + 4, y + 6, { width: cols[0] - 8 });
      doc.text(truncate(f.title, 28), colX[1] + 4, y + 6, { width: cols[1] - 8 });
      doc.text(findingCategory(f), colX[2] + 4, y + 6, { width: cols[2] - 8 });

      // Severity badge
      const sevBadgeX = colX[3] + 4;
      const sevLabel = f.severity.toUpperCase();
      const sevBadgeW = Math.min(55, sevLabel.length * 6.5 + 12);
      doc.roundedRect(sevBadgeX, y + 3, sevBadgeW, 14, 3).fill(severityColor(sevLabel));
      doc.fontSize(7).fillColor(COLORS.white)
        .text(sevLabel, sevBadgeX + 3, y + 6, { width: sevBadgeW - 6 });

      // OWASP mapping
      const owaspLabel = findingOwasp(f) || "-";
      doc.fontSize(8).fillColor(COLORS.textPrimary);
      doc.text(owaspLabel, colX[4] + 4, y + 6, { width: cols[4] - 8 });

      // Status with color coding
      const statusText = f.status || "OPEN";
      const statusUpper = statusText.toUpperCase().replace(/_/g, " ");
      let statusColor: string = COLORS.info;
      if (statusUpper === "OPEN") statusColor = COLORS.critical;
      else if (statusUpper === "FALSE_POSITIVE" || statusUpper === "FALSE POSITIVE") statusColor = COLORS.medium;
      else if (statusUpper === "CLOSED") statusColor = COLORS.green;
      const statusBadgeW = statusUpper.length * 5.5 + 12;
      doc.roundedRect(colX[5] + 4, y + 3, Math.min(statusBadgeW, cols[5] - 12), 14, 3)
        .fill(statusColor as string);
      doc.fontSize(6.5).fillColor(COLORS.white)
        .text(statusUpper, colX[5] + 6, y + 6, { width: cols[5] - 12 });

      y += 20;
    }
    y += 15;

    // ════════════════════════════════════════════════════════════════
    // SCOPE & COVERAGE
    // ════════════════════════════════════════════════════════════════
    if (y > 620) { doc.addPage(); y = 50; }
    y = drawSectionHeader(doc, "SCOPE & COVERAGE", marginL, y, contentW);
    y += 10;

    doc.fontSize(9).fillColor(COLORS.textSecondary)
      .text(
        `${scan.filesScanned} files and ${scan.depsScanned} dependencies scanned. Gate result: ${scan.gateResult}.`,
        marginL, y, { width: contentW },
      );
    y += 20;

    // Scanner coverage badges
    const scannerCounts = new Map<string, number>();
    for (const f of findings) {
      scannerCounts.set(f.scanner, (scannerCounts.get(f.scanner) || 0) + 1);
    }
    const allScanners = Object.keys(SCANNER_LABELS) as (keyof typeof SCANNER_LABELS)[];
    let badgeX = marginL;
    for (const s of allScanners) {
      const count = scannerCounts.get(s) || 0;
      const label = `${SCANNER_LABELS[s]} \u00B7 ${count > 0 ? count : "clean"}`;
      const bw = label.length * 5.5 + 16;
      if (badgeX + bw > marginL + contentW) { badgeX = marginL; y += 22; }
      const bg = count > 0 ? COLORS.mediumBg : COLORS.greenBg;
      const fg = count > 0 ? COLORS.medium : COLORS.green;
      doc.roundedRect(badgeX, y, bw, 18, 4).fillAndStroke(bg, COLORS.border);
      doc.fontSize(7).fillColor(fg).text(label, badgeX + 6, y + 5, { width: bw - 12 });
      badgeX += bw + 8;
    }
    y += 35;

    // ════════════════════════════════════════════════════════════════
    // OWASP TOP 10 COVERAGE
    // ════════════════════════════════════════════════════════════════
    if (y > 660) { doc.addPage(); y = 50; }
    y = drawSectionHeader(doc, "OWASP TOP 10 COVERAGE", marginL, y, contentW);
    y += 10;

    const owaspCounts = new Map<string, number>();
    for (const f of findings) {
      const o = findingOwasp(f);
      if (o) owaspCounts.set(o, (owaspCounts.get(o) || 0) + 1);
    }

    badgeX = marginL;
    const owaspNames: Record<string, string> = {
      "A01:2021": "Broken Access Control",
      "A02:2021": "Cryptographic Failures",
      "A03:2021": "Injection",
      "A04:2021": "Insecure Design",
      "A05:2021": "Security Misconfiguration",
      "A06:2021": "Vulnerable Components",
      "A07:2021": "Auth Failures",
      "A08:2021": "Software Integrity",
      "A09:2021": "Logging Failures",
      "A10:2021": "SSRF",
    };
    for (const [code, name] of Object.entries(owaspNames)) {
      const count = owaspCounts.get(code) || 0;
      const label = `${code} \u00B7 ${count > 0 ? count : "clean"}`;
      const bw = label.length * 5.5 + 16;
      if (badgeX + bw > marginL + contentW) { badgeX = marginL; y += 22; }
      const bg = count > 0 ? COLORS.mediumBg : COLORS.greenBg;
      const fg = count > 0 ? COLORS.medium : COLORS.green;
      doc.roundedRect(badgeX, y, bw, 18, 4).fillAndStroke(bg, COLORS.border);
      doc.fontSize(7).fillColor(fg).text(label, badgeX + 6, y + 5, { width: bw - 12 });
      badgeX += bw + 8;
    }
    y += 35;

    // ════════════════════════════════════════════════════════════════
    // REMEDIATION ROADMAP
    // ════════════════════════════════════════════════════════════════
    if (y > 580) { doc.addPage(); y = 50; }
    y = drawSectionHeader(doc, "REMEDIATION ROADMAP", marginL, y, contentW);
    y += 10;

    const criticalFindings = findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH");
    const mediumFindings = findings.filter((f) => f.severity === "MEDIUM");

    const colW = (contentW - 20) / 3;
    const roadmapHeaders = [
      { title: "NOW \u00B7 0\u201330 DAYS", color: COLORS.critical },
      { title: "SOON \u00B7 30\u201390 DAYS", color: COLORS.medium },
      { title: "LATER \u00B7 90+ DAYS", color: COLORS.textMuted },
    ];

    const roadmapY = y;
    roadmapHeaders.forEach((h, i) => {
      const cx = marginL + i * (colW + 10);
      doc.roundedRect(cx, roadmapY, colW, 16, 3).fill(COLORS.lightGray);
      doc.fontSize(8).fillColor(h.color)
        .text(h.title, cx + 8, roadmapY + 4, { width: colW - 16 });
    });
    y += 22;

    // Now column: unique remediation items from critical/high
    const nowItems = new Set<string>();
    for (const f of criticalFindings.slice(0, 8)) {
      const r = readReport(f.metadata);
      if (r?.remediation?.[0]) nowItems.add(truncate(r.remediation[0], 60));
    }
    const nowList = [...nowItems].slice(0, 5);
    const soonItems = new Set<string>();
    for (const f of mediumFindings.slice(0, 5)) {
      const r = readReport(f.metadata);
      if (r?.remediation?.[0]) soonItems.add(truncate(r.remediation[0], 60));
    }
    const soonList = [...soonItems].slice(0, 4);

    let maxColY = y;

    // Now column
    let cy = y;
    for (const item of nowList) {
      doc.fontSize(8).fillColor(COLORS.textSecondary)
        .text(`\u2022  ${item}`, marginL + 8, cy, { width: colW - 16 });
      cy = doc.y + 4;
    }
    if (nowList.length === 0) {
      doc.fontSize(8).fillColor(COLORS.textMuted).text("\u2022  Nothing scheduled", marginL + 8, cy, { width: colW - 16 });
      cy = doc.y + 4;
    }
    maxColY = Math.max(maxColY, cy);

    // Soon column
    cy = y;
    const col2X = marginL + colW + 10;
    for (const item of soonList) {
      doc.fontSize(8).fillColor(COLORS.textSecondary)
        .text(`\u2022  ${item}`, col2X + 8, cy, { width: colW - 16 });
      cy = doc.y + 4;
    }
    if (soonList.length === 0) {
      doc.fontSize(8).fillColor(COLORS.textMuted).text("\u2022  Nothing scheduled", col2X + 8, cy, { width: colW - 16 });
      cy = doc.y + 4;
    }
    maxColY = Math.max(maxColY, cy);

    // Later column
    const col3X = marginL + 2 * (colW + 10);
    doc.fontSize(8).fillColor(COLORS.textMuted)
      .text("\u2022  Nothing scheduled", col3X + 8, y, { width: colW - 16 });
    maxColY = Math.max(maxColY, doc.y + 4);

    y = maxColY + 20;

    // ════════════════════════════════════════════════════════════════
    // TECHNICAL FINDINGS — DETAILED EVIDENCE
    // ════════════════════════════════════════════════════════════════
    doc.addPage();
    y = 50;
    y = drawSectionHeader(doc, "TECHNICAL FINDINGS \u2014 DETAILED EVIDENCE", marginL, y, contentW);
    y += 10;

    for (const f of findings) {
      if (y > 580) { doc.addPage(); y = 50; }
      y = drawFindingCard(doc, f, marginL, y, contentW);
      y += 15;
    }

    // ════════════════════════════════════════════════════════════════
    // FOOTER
    // ════════════════════════════════════════════════════════════════
    doc.addPage();
    doc.fontSize(10).fillColor(COLORS.textMuted)
      .text(
        "Generated by Pepper \u00B7 Confidential \u2014 for the authorized recipient only.",
        marginL, 50, { width: contentW },
      );

    doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

// ─── Section Header ─────────────────────────────────────────────────
function drawSectionHeader(
  doc: PDFKit.PDFDocument, title: string, x: number, y: number, _w: number,
): number {
  doc.rect(x, y, 4, 16).fill(COLORS.sectionBar);
  doc.fontSize(10).fillColor(COLORS.textPrimary)
    .text(title, x + 12, y + 2);
  return y + 24;
}

// ─── Finding Card ───────────────────────────────────────────────────
function drawFindingCard(
  doc: PDFKit.PDFDocument, f: FindingData, x: number, startY: number, w: number,
): number {
  const report = readReport(f.metadata) || {
    vulnerabilityName: f.title,
    summary: f.description,
    stepsToReproduce: [],
    impact: "",
    remediation: [],
  };

  let y = startY;

  // Card border
  doc.save();

  // Meta line: ID · Status · Confidence
  const statusLabel = (f.status || "OPEN").replace(/_/g, " ");
  const confLabel = f.confidence ? `Confidence: ${(f.confidence * 100).toFixed(0)}%` : "";
  const metaLine = [f.ruleId || f.id.slice(0, 12), `Status: ${statusLabel}`, confLabel].filter(Boolean).join(" \u00B7 ");
  doc.fontSize(7).fillColor(COLORS.textMuted).text(metaLine, x, y, { width: w - 80 });

  // Severity badge (right side)
  const sevBadgeW = f.severity.length * 7 + 16;
  doc.roundedRect(x + w - sevBadgeW, y - 2, sevBadgeW, 18, 4).fill(severityColor(f.severity));
  doc.fontSize(8).fillColor(COLORS.white).text(f.severity, x + w - sevBadgeW, y + 2, { width: sevBadgeW, align: "center" });
  y += 16;

  // Title
  doc.fontSize(13).fillColor(COLORS.textPrimary)
    .text(truncate(report.vulnerabilityName || f.title, 80), x, y, { width: w });
  y = doc.y + 6;

  // Tags: CWE, OWASP, Category, Scanner
  let tagX = x;
  const tags: string[] = [];
  if (f.cweId) tags.push(f.cweId);
  const owasp = findingOwasp(f);
  if (owasp) tags.push(`OWASP ${owasp}`);
  tags.push(findingCategory(f));
  tags.push(scannerLabel(f.scanner));

  for (const tag of tags) {
    const tw = tag.length * 5 + 12;
    if (tagX + tw > x + w - 60) { tagX = x; y += 16; }
    doc.roundedRect(tagX, y, tw, 14, 3).fillAndStroke(COLORS.badgeBg, COLORS.badgeBorder);
    doc.fontSize(7).fillColor(COLORS.textSecondary).text(tag, tagX + 5, y + 3, { width: tw - 10 });
    tagX += tw + 5;
  }
  y += 22;

  // Summary
  if (report.summary) {
    doc.fontSize(8).fillColor(COLORS.textPrimary).text("Summary. ", x, y, { continued: true });
    doc.fillColor(COLORS.textSecondary).text(truncate(report.summary, 700), { width: w });
    y = doc.y + 8;
  }

  // Business Impact
  if (report.impact) {
    if (y > 700) { doc.addPage(); y = 50; }
    doc.fontSize(8).fillColor(COLORS.high).text("BUSINESS IMPACT", x, y);
    y += 12;
    const impactText = truncate(report.impact, 600);
    doc.fontSize(8);
    const impactBoxH = doc.heightOfString(impactText, { width: w - 16 }) + 12;
    if (y + impactBoxH > 770) { doc.addPage(); y = 50; }
    doc.roundedRect(x, y, w, impactBoxH, 4).fillAndStroke(COLORS.impactBg, COLORS.impactBorder);
    doc.fillColor(COLORS.high)
      .text(impactText, x + 8, y + 6, { width: w - 16 });
    y += impactBoxH + 8;
  }

  // Affected Location
  if (f.filePath) {
    doc.fontSize(8).fillColor(COLORS.high).text("AFFECTED LOCATION", x, y);
    y += 12;
    const loc = f.filePath + (f.startLine ? `:${f.startLine}` : "");
    doc.fontSize(8).fillColor(COLORS.textSecondary).text(loc, x, y, { width: w });
    y = doc.y + 8;
  }

  // Proof of Concept / Snippet
  if (f.snippet) {
    if (y > 680) { doc.addPage(); y = 50; }
    doc.fontSize(8).fillColor(COLORS.high).text("PROOF OF CONCEPT", x, y);
    y += 12;
    const snippetText = truncate(f.snippet.trim(), 600);
    doc.fontSize(7);
    const snippetH = doc.heightOfString(snippetText, { width: w - 16 }) + 12;
    if (y + snippetH > 770) { doc.addPage(); y = 50; }
    doc.roundedRect(x, y, w, snippetH, 4).fill(COLORS.pocBg);
    doc.fillColor(COLORS.pocText)
      .text(snippetText, x + 8, y + 6, { width: w - 16 });
    y += snippetH + 8;
  }

  // Steps to Reproduce (only for SAST and Zero-Day)
  if ((f.scanner === "SAST_LLM" || f.scanner === "ZERO_DAY") && report.stepsToReproduce.length > 0) {
    if (y > 700) { doc.addPage(); y = 50; }
    doc.fontSize(8).fillColor(COLORS.high).text("STEPS TO REPRODUCE", x, y);
    y += 12;
    let stepY = y;
    for (let i = 0; i < report.stepsToReproduce.length; i++) {
      if (stepY > 730) { doc.addPage(); stepY = 50; }
      const step = truncate(report.stepsToReproduce[i], 200);
      doc.fontSize(7).fillColor(COLORS.textSecondary)
        .text(`${i + 1}. ${step}`, x, stepY, { width: w });
      stepY = doc.y + 4;
    }
    y = stepY + 4;
  }

  // Remediation
  if (report.remediation.length > 0) {
    if (y > 700) { doc.addPage(); y = 50; }
    doc.fontSize(8).fillColor(COLORS.high).text("REMEDIATION", x, y);
    y += 12;
    // Render each remediation step on its own line so multi-step guidance is
    // readable instead of running together in a single paragraph.
    const remText = report.remediation
      .map((r) => `• ${truncate(r, 400)}`)
      .join("\n");
    doc.fontSize(8);
    const remH = doc.heightOfString(remText, { width: w - 16 }) + 12;
    if (y + remH > 770) { doc.addPage(); y = 50; }
    doc.roundedRect(x, y, w, remH, 4).fillAndStroke(COLORS.remedBg, COLORS.remedBorder);
    doc.fillColor(COLORS.textSecondary)
      .text(remText, x + 8, y + 6, { width: w - 16 });
    y += remH + 8;
  }

  // Confidence Analysis
  if (f.confidence !== null && f.confidence !== undefined) {
    if (y > 700) { doc.addPage(); y = 50; }
    const confPct = Math.round(f.confidence * 100);
    let confLabel = "CONFIDENCE";
    let confColor: string = COLORS.medium;
    if (confPct >= 95) { confColor = COLORS.critical; confLabel += " (VERY HIGH)"; }
    else if (confPct >= 80) { confColor = COLORS.high; confLabel += " (HIGH)"; }
    else if (confPct >= 60) { confColor = COLORS.medium; confLabel += " (MEDIUM)"; }
    else { confColor = COLORS.low; confLabel += " (LOW)"; }

    doc.fontSize(8).fillColor(confColor as string).text(confLabel, x, y);
    y += 12;

    const confBar = Math.max(10, (confPct / 100) * (w - 60));
    doc.roundedRect(x, y, w - 60, 12, 2).fillAndStroke(COLORS.lightGray, COLORS.border);
    doc.roundedRect(x, y, confBar, 12, 2).fill(confColor as string);
    doc.fontSize(7).fillColor(COLORS.textPrimary).text(`${confPct}%`, x + w - 45, y + 2);
    y += 18;
  }

  // Separator
  doc.moveTo(x, y).lineTo(x + w, y).strokeColor(COLORS.border).lineWidth(0.5).stroke();
  y += 4;

  doc.restore();
  return y;
}
