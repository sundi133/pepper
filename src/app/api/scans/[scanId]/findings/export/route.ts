import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  enrichFindingWithReport,
  findingHasStoredReport,
} from "@/lib/finding-report";
import { SCANNER_LABELS } from "@/lib/constants";

type ReportFinding = {
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

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { searchParams } = new URL(req.url);
  const format = searchParams.get("format") || "csv";

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: {
      id: true,
      status: true,
      scanType: true,
      branch: true,
      commitSha: true,
      sourceType: true,
      sourceRef: true,
      gateResult: true,
      createdAt: true,
      completedAt: true,
      filesScanned: true,
      depsScanned: true,
      project: { select: { name: true } },
    },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const rawFindings = await prisma.finding.findMany({
    where: { scanId },
    orderBy: [{ severity: "asc" }, { scanner: "asc" }, { filePath: "asc" }],
  });
  const findings = rawFindings.map(enrichFindingWithReport);
  await Promise.allSettled(
    findings
      .filter((_finding, index) => !findingHasStoredReport(rawFindings[index]))
      .map((finding) =>
        prisma.finding.update({
          where: { id: finding.id },
          data: { metadata: finding.metadata as object },
        }),
      ),
  );

  const timestamp = new Date().toISOString().slice(0, 10);
  const projectSlug = (scan.project?.name || "scan").replace(
    /[^a-zA-Z0-9_-]/g,
    "_",
  );

  if (format === "json") {
    return new NextResponse(JSON.stringify(findings, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="${projectSlug}-findings-${timestamp}.json"`,
      },
    });
  }

  if (format === "html") {
    return new NextResponse(buildHtmlReport({ scan, findings }), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Disposition": `inline; filename="${projectSlug}-findings-${timestamp}.html"`,
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
      },
    });
  }

  const csvHeader = [
    "Severity",
    "Scanner",
    "Title",
    "Description",
    "File Path",
    "Start Line",
    "End Line",
    "Rule ID",
    "CWE ID",
    "CVE ID",
    "Confidence",
    "Snippet",
  ].join(",");

  const csvRows = findings.map((f) =>
    [
      f.severity,
      f.scanner,
      csvEscape(f.title),
      csvEscape(f.description),
      csvEscape(f.filePath || ""),
      f.startLine ?? "",
      f.endLine ?? "",
      csvEscape(f.ruleId || ""),
      csvEscape(f.cweId || ""),
      csvEscape(f.cveId || ""),
      f.confidence != null ? f.confidence.toFixed(2) : "",
      csvEscape(f.snippet || ""),
    ].join(","),
  );

  const csv = [csvHeader, ...csvRows].join("\n");

  return new NextResponse(csv, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="${projectSlug}-findings-${timestamp}.csv"`,
    },
  });
}

function csvEscape(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function buildHtmlReport({
  scan,
  findings,
}: {
  scan: {
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
    project: { name: string } | null;
  };
  findings: ReportFinding[];
}): string {
  const generatedAt = new Date();
  const counts = countFindingsBySeverity(findings);
  const grouped = groupFindingsByScanner(findings);
  const projectName = scan.project?.name || "Scan";
  const source = scan.sourceType === "SVN_CHECKOUT" && scan.sourceRef
    ? `SVN ${scan.sourceRef}`
    : scan.branch
      ? `Branch ${scan.branch}`
      : scan.sourceType;
  const commit = scan.commitSha ? scan.commitSha.slice(0, 12) : "N/A";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(projectName)} Findings Report</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f7fb;
      --panel: #ffffff;
      --ink: #172033;
      --muted: #667085;
      --line: #d9e2ef;
      --brand: #0f766e;
      --brand-dark: #134e4a;
      --critical: #b42318;
      --high: #c2410c;
      --medium: #b7791f;
      --low: #2563eb;
      --info: #475467;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.55;
    }
    .page { max-width: 1180px; margin: 0 auto; padding: 40px 28px 56px; }
    .hero {
      overflow: hidden;
      border-radius: 28px;
      background: linear-gradient(135deg, #0f172a 0%, #134e4a 56%, #0f766e 100%);
      color: #fff;
      box-shadow: 0 24px 60px rgba(15, 23, 42, 0.22);
    }
    .hero-inner { padding: 38px; }
    .eyebrow { margin: 0 0 10px; color: #b7f7ed; font-size: 12px; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
    h1 { margin: 0; font-size: clamp(32px, 5vw, 56px); line-height: 1.04; letter-spacing: -0.04em; }
    .subtitle { max-width: 820px; margin: 18px 0 0; color: #d5fff9; font-size: 16px; }
    .hero-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-top: 30px; }
    .hero-card { border: 1px solid rgba(255,255,255,.18); border-radius: 18px; background: rgba(255,255,255,.1); padding: 16px; }
    .hero-card span { display: block; color: #b7f7ed; font-size: 12px; font-weight: 700; text-transform: uppercase; }
    .hero-card strong { display: block; margin-top: 5px; font-size: 18px; word-break: break-word; }
    .section { margin-top: 28px; border: 1px solid var(--line); border-radius: 24px; background: var(--panel); box-shadow: 0 16px 45px rgba(16,24,40,.07); }
    .section-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; border-bottom: 1px solid var(--line); padding: 24px 28px; }
    h2 { margin: 0; font-size: 22px; letter-spacing: -0.02em; }
    .muted { color: var(--muted); }
    .summary-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; padding: 24px 28px; }
    .metric { border: 1px solid var(--line); border-radius: 18px; padding: 18px; background: #fbfdff; }
    .metric span { display: block; color: var(--muted); font-size: 12px; font-weight: 800; text-transform: uppercase; }
    .metric strong { display: block; margin-top: 8px; font-size: 30px; line-height: 1; }
    .critical { color: var(--critical); } .high { color: var(--high); } .medium { color: var(--medium); } .low { color: var(--low); } .info { color: var(--info); }
    .details { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; padding: 0 28px 28px; }
    .detail { border: 1px solid var(--line); border-radius: 16px; padding: 14px 16px; }
    .detail span { display: block; color: var(--muted); font-size: 12px; font-weight: 700; }
    .detail strong { display: block; margin-top: 4px; word-break: break-word; }
    .scanner-group { padding: 24px 28px 30px; }
    .scanner-group + .scanner-group { border-top: 1px solid var(--line); }
    .scanner-title { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 16px; }
    .badge { display: inline-flex; align-items: center; border-radius: 999px; padding: 5px 10px; background: #eef6ff; color: #175cd3; font-size: 12px; font-weight: 800; }
    .finding { border: 1px solid var(--line); border-radius: 20px; background: #fff; overflow: hidden; }
    .finding + .finding { margin-top: 16px; }
    .finding-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; background: #fbfdff; border-bottom: 1px solid var(--line); padding: 20px; }
    .finding h3 { margin: 8px 0 0; font-size: 19px; line-height: 1.3; }
    .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
    .chip { border: 1px solid var(--line); border-radius: 999px; padding: 4px 9px; color: var(--muted); font-size: 12px; font-weight: 700; }
    .sev { border-radius: 999px; padding: 6px 11px; color: #fff; font-size: 12px; font-weight: 900; letter-spacing: .04em; text-transform: uppercase; }
    .sev-critical { background: var(--critical); } .sev-high { background: var(--high); } .sev-medium { background: var(--medium); } .sev-low { background: var(--low); } .sev-info { background: var(--info); }
    .finding-body { padding: 22px; }
    .report-block {
      border-left: 4px solid #ccfbf1;
      border-radius: 14px;
      background: #fbfdff;
      padding: 16px 18px;
    }
    .report-block + .report-block { margin-top: 16px; }
    .report-block h4 { margin: 0 0 8px; color: var(--brand-dark); font-size: 12px; font-weight: 900; letter-spacing: .12em; text-transform: uppercase; }
    .report-text { margin: 0; color: #344054; white-space: pre-wrap; overflow-wrap: anywhere; }
    ol { margin: 0; padding-left: 22px; color: #344054; }
    li + li { margin-top: 8px; }
    pre { margin: 0; max-height: 440px; overflow: auto; border-radius: 16px; background: #0b1020; color: #e6edf6; padding: 18px; font-size: 12px; line-height: 1.6; white-space: pre-wrap; overflow-wrap: anywhere; box-shadow: inset 0 0 0 1px rgba(255,255,255,.08); }
    .evidence-card {
      margin-top: 18px;
      border: 1px solid #b7d7ff;
      border-left: 4px solid var(--low);
      border-radius: 16px;
      background: linear-gradient(180deg, #f8fbff 0%, #ffffff 100%);
      padding: 18px;
    }
    .evidence-card h4 { margin: 0 0 10px; color: #1849a9; font-size: 12px; font-weight: 900; letter-spacing: .12em; text-transform: uppercase; }
    .empty { padding: 34px 28px; text-align: center; color: var(--muted); }
    .footer { margin-top: 26px; color: var(--muted); font-size: 12px; text-align: center; }
    @media print {
      body { background: #fff; }
      .page { max-width: none; padding: 0; }
      .hero, .section { box-shadow: none; break-inside: avoid; }
      .finding { break-inside: avoid; }
    }
    @media (max-width: 900px) {
      .hero-grid, .summary-grid, .details { grid-template-columns: 1fr; }
      .section-header, .finding-head, .scanner-title { flex-direction: column; align-items: flex-start; }
    }
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div class="hero-inner">
        <p class="eyebrow">Pepper Security Findings Report</p>
        <h1>${escapeHtml(projectName)}</h1>
        <p class="subtitle">Professional HTML report for scan ${escapeHtml(scan.id)}. Generated ${formatDate(generatedAt)} with ${findings.length} findings across ${grouped.length} scanner groups.</p>
        <div class="hero-grid">
          ${renderHeroCard("Scan Type", scan.scanType)}
          ${renderHeroCard("Status", scan.status)}
          ${renderHeroCard("Gate Result", scan.gateResult)}
          ${renderHeroCard("Commit", commit)}
        </div>
      </div>
    </section>

    <section class="section">
      <div class="section-header">
        <div>
          <h2>Executive Summary</h2>
          <p class="muted">Severity distribution and scan context for triage.</p>
        </div>
        <span class="badge">${findings.length} total findings</span>
      </div>
      <div class="summary-grid">
        ${renderMetric("Critical", counts.CRITICAL, "critical")}
        ${renderMetric("High", counts.HIGH, "high")}
        ${renderMetric("Medium", counts.MEDIUM, "medium")}
        ${renderMetric("Low", counts.LOW, "low")}
        ${renderMetric("Info", counts.INFO, "info")}
      </div>
      <div class="details">
        ${renderDetail("Source", source)}
        ${renderDetail("Created", formatDate(scan.createdAt))}
        ${renderDetail("Completed", scan.completedAt ? formatDate(scan.completedAt) : "N/A")}
        ${renderDetail("Files Scanned", String(scan.filesScanned))}
        ${renderDetail("Dependencies Scanned", String(scan.depsScanned))}
        ${renderDetail("Generated", formatDate(generatedAt))}
      </div>
    </section>

    <section class="section">
      <div class="section-header">
        <div>
          <h2>Findings</h2>
          <p class="muted">Each finding includes summary, reproduction guidance, impact, remediation, and code evidence when available.</p>
        </div>
      </div>
      ${
        grouped.length === 0
          ? `<div class="empty">No findings were detected for this scan.</div>`
          : grouped.map(renderScannerGroup).join("")
      }
    </section>

    <p class="footer">Generated by Pepper. Treat reproduced vulnerabilities only in authorized environments.</p>
  </main>
</body>
</html>`;
}

function renderHeroCard(label: string, value: string): string {
  return `<div class="hero-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function renderMetric(label: string, value: number, className: string): string {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong class="${className}">${value}</strong></div>`;
}

function renderDetail(label: string, value: string): string {
  return `<div class="detail"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function renderScannerGroup(group: {
  scanner: string;
  label: string;
  findings: ReportFinding[];
}): string {
  return `<div class="scanner-group">
    <div class="scanner-title">
      <h2>${escapeHtml(group.label)}</h2>
      <span class="badge">${group.findings.length} findings</span>
    </div>
    ${group.findings.map(renderFinding).join("")}
  </div>`;
}

function renderFinding(finding: ReportFinding): string {
  const report = readStoredReport(finding.metadata) || fallbackReport(finding);
  const location = formatLocation(finding);
  const chips = [
    finding.status ? `Status: ${finding.status.replace(/_/g, " ")}` : "",
    finding.ruleId ? `Rule: ${finding.ruleId}` : "",
    finding.cweId || "",
    finding.cveId || "",
    location ? `Location: ${location}` : "",
    finding.confidence != null ? `Confidence: ${Math.round(finding.confidence * 100)}%` : "",
  ].filter(Boolean);

  return `<article class="finding">
    <div class="finding-head">
      <div>
        <span class="sev sev-${finding.severity.toLowerCase()}">${escapeHtml(finding.severity)}</span>
        <h3>${escapeHtml(report.vulnerabilityName || finding.title)}</h3>
        <div class="chips">${chips.map((chip) => `<span class="chip">${escapeHtml(chip)}</span>`).join("")}</div>
      </div>
      <span class="badge">${escapeHtml(scannerLabel(finding.scanner))}</span>
    </div>
    <div class="finding-body">
      ${renderReportBlock("Summary", report.summary)}
      ${renderListBlock("Steps to Reproduce", report.stepsToReproduce)}
      ${renderReportBlock("Impact", report.impact)}
      ${renderListBlock("Remediation", report.remediation)}
      ${renderEvidenceBlock(finding)}
    </div>
  </article>`;
}

function renderReportBlock(title: string, text: string): string {
  return `<section class="report-block"><h4>${escapeHtml(title)}</h4><p class="report-text">${escapeHtml(text || "N/A")}</p></section>`;
}

function renderListBlock(title: string, items: string[]): string {
  if (items.length === 0) return "";
  return `<section class="report-block"><h4>${escapeHtml(title)}</h4><ol>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ol></section>`;
}

function renderEvidenceBlock(finding: ReportFinding): string {
  if (!finding.snippet) return "";
  return `<section class="evidence-card"><h4>Code Evidence</h4><pre>${escapeHtml(finding.snippet)}</pre></section>`;
}

function countFindingsBySeverity(findings: ReportFinding[]) {
  return findings.reduce(
    (counts, finding) => {
      if (finding.severity in counts) {
        counts[finding.severity as keyof typeof counts] += 1;
      }
      return counts;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  );
}

function groupFindingsByScanner(findings: ReportFinding[]) {
  const groups = new Map<string, ReportFinding[]>();
  for (const finding of findings) {
    groups.set(finding.scanner, [...(groups.get(finding.scanner) || []), finding]);
  }
  return Array.from(groups.entries()).map(([scanner, groupFindings]) => ({
    scanner,
    label: scannerLabel(scanner),
    findings: groupFindings,
  }));
}

function readStoredReport(metadata: unknown): StoredReport | undefined {
  const data = metadata && typeof metadata === "object" && !Array.isArray(metadata)
    ? (metadata as Record<string, unknown>)
    : {};
  const value = data.reportSections;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const report = value as Record<string, unknown>;
  if (
    typeof report.vulnerabilityName !== "string" ||
    typeof report.summary !== "string" ||
    typeof report.impact !== "string" ||
    !Array.isArray(report.remediation)
  ) {
    return undefined;
  }
  return {
    vulnerabilityName: report.vulnerabilityName,
    summary: report.summary,
    stepsToReproduce: Array.isArray(report.stepsToReproduce)
      ? report.stepsToReproduce.filter((step): step is string => typeof step === "string")
      : [],
    impact: report.impact,
    remediation: report.remediation.filter((step): step is string => typeof step === "string"),
  };
}

function fallbackReport(finding: ReportFinding): StoredReport {
  return {
    vulnerabilityName: finding.title,
    summary: finding.description,
    stepsToReproduce: [],
    impact:
      "Based on the available scanner evidence, this finding may affect application confidentiality, integrity, or availability.",
    remediation: [
      "Review the affected code or dependency, apply the required security control, and add regression coverage for the vulnerable path.",
    ],
  };
}

function formatLocation(finding: ReportFinding): string {
  if (!finding.filePath) return "";
  if (!finding.startLine) return finding.filePath;
  return `${finding.filePath}:${finding.startLine}${
    finding.endLine && finding.endLine !== finding.startLine
      ? `-${finding.endLine}`
      : ""
  }`;
}

function scannerLabel(scanner: string): string {
  return SCANNER_LABELS[scanner as keyof typeof SCANNER_LABELS] || scanner;
}

function formatDate(date: Date): string {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
