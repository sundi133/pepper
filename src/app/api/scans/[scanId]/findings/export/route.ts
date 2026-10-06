import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  enrichFindingWithReport,
  findingHasStoredReport,
} from "@/lib/finding-report";
import { SCANNER_LABELS } from "@/lib/constants";
import { buildPdfReport } from "@/lib/pdf-report";
import { isKnownSection } from "@/lib/finding-sections";

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
  const isPauseExport = searchParams.get("pause") === "true";
  // Comma-separated section ids (SAST,SECRETS,...). Unknown ids are dropped so
  // a stale or tampered value can never crash the report builder.
  const sections = (searchParams.get("sections") || "")
    .split(",")
    .map((s) => s.trim())
    .filter(isKnownSection);

  if (format === "json") {
    return NextResponse.json(
      { error: "JSON export is not supported. Use format=csv or format=html." },
      { status: 400 },
    );
  }

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
      criticalCount: true,
      highCount: true,
      mediumCount: true,
      lowCount: true,
      infoCount: true,
      project: { select: { name: true, repoUrl: true } },
    },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const rawFindings = await prisma.finding.findMany({
    where: { scanId, scan: { project: { organizationId: orgId } } },
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

  if (format === "pdf") {
    try {
      // Add pause status to scan metadata for report
      const scanForReport = isPauseExport
        ? { ...scan, status: `${scan.status} (Paused)` }
        : scan;

      const pdfBuffer = await buildPdfReport(scanForReport, findings, {
        sections,
      });
      const filename = isPauseExport
        ? `${projectSlug}-paused-report-${timestamp}.pdf`
        : `${projectSlug}-report-${timestamp}.pdf`;

      return new NextResponse(new Uint8Array(pdfBuffer), {
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": `inline; filename="${filename}"`,
          "Cache-Control": "no-store",
        },
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const stack = e instanceof Error ? e.stack : "";
      console.error("PDF report generation failed:", msg, stack);
      return NextResponse.json(
        { error: "Failed to generate PDF report", detail: msg },
        { status: 500 },
      );
    }
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
    filesScanned?: number | null;
    depsScanned?: number | null;
    criticalCount?: number | null;
    highCount?: number | null;
    mediumCount?: number | null;
    lowCount?: number | null;
    infoCount?: number | null;
    project: { name: string; repoUrl: string | null } | null;
  };
  findings: ReportFinding[];
}): string {
  const generatedAt = new Date();
  const projectName = scan.project?.name || "Scan";
  const repoUrl = safeHttpUrl(scan.project?.repoUrl ?? undefined);
  const repoDisplay = scan.project?.repoUrl?.trim() || "";
  const lastScanAt = scan.completedAt ?? scan.createdAt;
  const sourceLine =
    scan.sourceType === "SVN_CHECKOUT" && scan.sourceRef
      ? `SVN ${scan.sourceRef}`
      : scan.branch
        ? `Branch ${scan.branch}${scan.commitSha ? ` · ${scan.commitSha.slice(0, 12)}` : ""}`
        : scan.sourceType;

  // Compute metrics from findings
  const critCount = findings.filter((f) => f.severity.toUpperCase() === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity.toUpperCase() === "HIGH").length;
  const medCount = findings.filter((f) => f.severity.toUpperCase() === "MEDIUM").length;
  const lowCount = findings.filter((f) => f.severity.toUpperCase() === "LOW").length;
  const totalFindings = findings.length;

  // Scanner category breakdown
  const sastCount = findings.filter((f) => f.scanner.toUpperCase().startsWith("SAST")).length;
  const scaCount = findings.filter(
    (f) => f.scanner.toUpperCase().startsWith("SCA") || f.scanner.toUpperCase() === "DEPENDENCY",
  ).length;
  const secretsCount = findings.filter((f) => f.scanner.toUpperCase().startsWith("SECRET")).length;
  const iacCount = findings.filter((f) => f.scanner.toUpperCase().startsWith("IAC")).length;
  const containerCount = findings.filter((f) => f.scanner.toUpperCase().includes("CONTAINER")).length;

  const isGatePassed = scan.gateResult.toUpperCase() === "PASSED";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(`Pepper SAST · Security Assessment Report — ${projectName}`)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background: #f8fafc; padding: 2rem; }
    .container { max-width: 1040px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); padding: 2.5rem; }
    
    /* Header & Branding */
    .header-card { border-bottom: 2px solid #e2e8f0; padding-bottom: 1.5rem; margin-bottom: 1.5rem; }
    .brand-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 0.5rem; }
    .brand { font-size: 1.1rem; font-weight: 700; color: #0f172a; display: flex; align-items: center; gap: 0.5rem; }
    .brand-logo { font-size: 1.3rem; }
    .header-badges { display: flex; align-items: center; gap: 0.5rem; }
    .project-hero { display: flex; justify-content: space-between; align-items: baseline; flex-wrap: wrap; gap: 0.75rem; }
    h1 { font-size: 1.85rem; color: #0f172a; font-weight: 800; }
    .meta-row { display: flex; flex-wrap: wrap; gap: 1.5rem; color: #64748b; font-size: 0.875rem; margin-top: 0.75rem; }
    .meta-row a { color: #4f46e5; text-decoration: none; word-break: break-all; }
    .meta-row a:hover { text-decoration: underline; }

    /* Badges */
    .badge { padding: 0.25rem 0.65rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; display: inline-flex; align-items: center; }
    .badge-gate-passed { background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }
    .badge-gate-failed { background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }
    .badge-status { background: #f1f5f9; color: #475569; text-transform: capitalize; border: 1px solid #e2e8f0; }
    .badge-sev-critical { background: #fee2e2; color: #dc2626; border: 1px solid #fca5a5; }
    .badge-sev-high { background: #ffedd5; color: #ea580c; border: 1px solid #fdba74; }
    .badge-sev-medium { background: #fef3c7; color: #d97706; border: 1px solid #fcd34d; }
    .badge-sev-low { background: #dcfce7; color: #16a34a; border: 1px solid #86efac; }
    .badge-sev-info { background: #e0f2fe; color: #0284c7; border: 1px solid #bae6fd; }
    .badge-scanner { background: #f1f5f9; color: #334155; font-size: 0.75rem; font-weight: 600; text-transform: none; border: 1px solid #cbd5e1; }
    .badge-cwe, .badge-cve { background: #e0e7ff; color: #4338ca; text-decoration: none; font-size: 0.75rem; font-weight: 600; border: 1px solid #c7d2fe; text-transform: none; }
    .badge-cwe:hover, .badge-cve:hover { text-decoration: underline; }
    .badge-confidence { background: #f8fafc; color: #475569; font-size: 0.75rem; border: 1px solid #e2e8f0; font-weight: 600; text-transform: none; }

    /* Metrics Grid */
    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem; }
    .metric-card { padding: 1rem; border-radius: 8px; border: 1px solid #e2e8f0; background: #f8fafc; text-align: center; }
    .metric-critical { border-left: 4px solid #dc2626; }
    .metric-high { border-left: 4px solid #ea580c; }
    .metric-medium { border-left: 4px solid #d97706; }
    .metric-low { border-left: 4px solid #16a34a; }
    .metric-total { border-left: 4px solid #4f46e5; }
    .metric-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: #64748b; margin-bottom: 0.25rem; }
    .metric-val { font-size: 1.6rem; font-weight: 800; color: #0f172a; line-height: 1.2; }

    /* Category breakdown pills */
    .scanner-pills-row { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin-bottom: 2rem; padding: 0.75rem 1rem; background: #f1f5f9; border-radius: 8px; font-size: 0.85rem; }
    .pills-label { font-weight: 600; color: #475569; }
    .scanner-pill { background: white; padding: 0.25rem 0.65rem; border-radius: 9999px; font-weight: 600; color: #334155; border: 1px solid #cbd5e1; font-size: 0.8rem; }

    /* Findings section */
    h2 { font-size: 1.25rem; color: #0f172a; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #e2e8f0; }
    .vuln-card { border: 1px solid #e2e8f0; border-radius: 10px; padding: 1.25rem; margin-bottom: 1.25rem; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.03); }
    .vuln-header { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin-bottom: 0.6rem; }
    .vuln-header strong { font-size: 1.05rem; color: #0f172a; flex: 1 1 300px; }
    .loc-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
    .loc { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.825rem; color: #475569; background: #f1f5f9; padding: 0.15rem 0.4rem; border-radius: 4px; border: 1px solid #e2e8f0; word-break: break-all; }
    .loc-scanner { font-size: 0.8rem; color: #64748b; }

    /* Notice pattern */
    .notice-pattern { background: #fefce8; border: 1px solid #fef08a; border-radius: 6px; padding: 0.5rem 0.75rem; font-size: 0.825rem; color: #854d0e; margin-bottom: 0.75rem; }

    /* Code evidence */
    .evidence-box { background: #0f172a; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.75rem; overflow-x: auto; }
    .evidence-header { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; color: #94a3b8; margin-bottom: 0.35rem; }
    .evidence-code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.8rem; color: #e2e8f0; white-space: pre-wrap; word-break: break-all; }

    /* SCA & Secrets info boxes */
    .sca-details-box, .secret-details-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.75rem; font-size: 0.85rem; }
    .sca-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem; }
    .meta-label { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; color: #64748b; display: block; margin-bottom: 0.2rem; }
    .meta-val { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.825rem; color: #0f172a; }
    .fixed-ver { color: #16a34a; font-weight: 700; }
    .usage-locations-box { margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid #e2e8f0; }
    .usage-item { margin-top: 0.35rem; }
    .usage-file { font-weight: 600; color: #334155; font-size: 0.8rem; }
    .usage-code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.75rem; color: #475569; background: #e2e8f0; padding: 0.2rem 0.4rem; border-radius: 4px; display: block; margin-top: 0.15rem; overflow-x: auto; }
    .secret-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.25rem; }
    .secret-type-badge { font-weight: 600; color: #0f172a; }
    .secret-mask { font-family: monospace; background: #fee2e2; color: #dc2626; padding: 0.1rem 0.35rem; border-radius: 4px; font-weight: 700; }
    .secret-warning { font-size: 0.8rem; color: #b91c1c; }

    /* Card fields */
    .field { margin-bottom: 0.75rem; }
    .field .label { font-weight: 700; color: #0f172a; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.025em; margin-bottom: 0.25rem; display: block; }
    .field .body { color: #334155; font-size: 0.9rem; line-height: 1.55; white-space: pre-wrap; overflow-wrap: anywhere; }
    .field .body strong { color: #0f172a; }

    /* Steps to reproduce */
    .repro-steps { margin-top: 0.35rem; }
    .repro-step { margin-top: 0.65rem; padding-top: 0.65rem; border-top: 1px solid #f1f5f9; }
    .repro-step:first-child { margin-top: 0; padding-top: 0; border-top: none; }
    .repro-step .step-tag { font-weight: 700; color: #4338ca; font-size: 0.825rem; margin-bottom: 0.2rem; }
    .code-block { background: #0f172a; color: #f8fafc; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.8rem; padding: 0.65rem; border-radius: 6px; margin-top: 0.35rem; overflow-x: auto; }

    /* Remediation list */
    ol.remed { margin: 0.35rem 0 0 1.25rem; color: #334155; font-size: 0.9rem; }
    ol.remed li { margin-top: 0.35rem; }

    .empty { text-align: center; color: #64748b; padding: 3rem; font-size: 0.95rem; }
    .footer { margin-top: 2.5rem; padding-top: 1.25rem; border-top: 1px solid #e2e8f0; text-align: center; color: #64748b; font-size: 0.85rem; }
    @media print { body { background: #fff; padding: 0; } .container { box-shadow: none; padding: 1rem; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header-card">
      <div class="brand-row">
        <div class="brand">
          <span class="brand-logo">🌶️</span>
          <span>Pepper SAST · Security Assessment Report</span>
        </div>
        <div class="header-badges">
          <span class="badge ${isGatePassed ? "badge-gate-passed" : "badge-gate-failed"}">Gate ${escapeHtml(scan.gateResult.toUpperCase())}</span>
          <span class="badge badge-status">${escapeHtml(scan.status)}</span>
        </div>
      </div>
      <div class="project-hero">
        <h1>${escapeHtml(projectName)}</h1>
        <span class="badge badge-scanner">${escapeHtml(scan.scanType)} Scan</span>
      </div>
      <div class="meta-row">
        ${
          repoUrl
            ? `<span><strong>Repository:</strong> <a href="${escapeHtml(repoUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(repoUrl)}</a></span>`
            : repoDisplay
              ? `<span><strong>Repository:</strong> ${escapeHtml(repoDisplay)}</span>`
              : ""
        }
        <span><strong>Source:</strong> ${escapeHtml(sourceLine)}</span>
        <span><strong>Last scan:</strong> ${escapeHtml(formatDate(lastScanAt))}</span>
        ${scan.filesScanned != null ? `<span><strong>Files:</strong> ${scan.filesScanned}</span>` : ""}
        ${scan.depsScanned != null ? `<span><strong>Deps:</strong> ${scan.depsScanned}</span>` : ""}
      </div>
    </div>

    <div class="metrics-grid">
      <div class="metric-card metric-critical">
        <div class="metric-label">Critical</div>
        <div class="metric-val">${critCount}</div>
      </div>
      <div class="metric-card metric-high">
        <div class="metric-label">High</div>
        <div class="metric-val">${highCount}</div>
      </div>
      <div class="metric-card metric-medium">
        <div class="metric-label">Medium</div>
        <div class="metric-val">${medCount}</div>
      </div>
      <div class="metric-card metric-low">
        <div class="metric-label">Low</div>
        <div class="metric-val">${lowCount}</div>
      </div>
      <div class="metric-card metric-total">
        <div class="metric-label">Total Findings</div>
        <div class="metric-val">${totalFindings}</div>
      </div>
    </div>

    <div class="scanner-pills-row">
      <span class="pills-label">Scanner Breakdown:</span>
      ${sastCount > 0 ? `<span class="scanner-pill">SAST Findings (${sastCount})</span>` : ""}
      ${scaCount > 0 ? `<span class="scanner-pill">SCA Findings (${scaCount})</span>` : ""}
      ${secretsCount > 0 ? `<span class="scanner-pill">Secrets Findings (${secretsCount})</span>` : ""}
      ${iacCount > 0 ? `<span class="scanner-pill">IaC Findings (${iacCount})</span>` : ""}
      ${containerCount > 0 ? `<span class="scanner-pill">Container Findings (${containerCount})</span>` : ""}
    </div>

    <h2>Vulnerabilities (${findings.length})</h2>
    ${
      findings.length === 0
        ? `<p class="empty">No findings were detected for this scan.</p>`
        : findings.map(renderVulnCard).join("")
    }

    <div class="footer">Generated ${escapeHtml(formatDate(generatedAt))} · Pepper SAST — reproduce only in authorized environments.</div>
  </div>
</body>
</html>`;
}

function safeHttpUrl(url: string | undefined): string | null {
  if (!url) return null;
  const t = url.trim();
  if (/^https:\/\//i.test(t) || /^http:\/\//i.test(t)) return t;
  return null;
}

function severityBadgeClass(sev: string): string {
  const s = sev.toUpperCase();
  if (s === "CRITICAL") return "badge-sev-critical";
  if (s === "HIGH") return "badge-sev-high";
  if (s === "MEDIUM") return "badge-sev-medium";
  if (s === "LOW") return "badge-sev-low";
  return "badge-sev-info";
}

function formatSummaryHtml(summary: string): string {
  return summary
    .split(/\n\n+/)
    .map((para) => {
      const match = para.match(
        /^(What is wrong|Where|Why it is exploitable|How to validate the fix|Attack path|Fix):\s*([\s\S]*)$/i,
      );
      if (match) {
        return `<strong>${escapeHtml(match[1])}:</strong> ${escapeHtml(match[2].trim())}`;
      }
      return escapeHtml(para);
    })
    .join("<br><br>");
}

function renderVulnCard(finding: ReportFinding): string {
  const report = readStoredReport(finding.metadata, finding) || fallbackReport(finding);
  const location = formatLocation(finding);
  const statusLabel = (finding.status || "OPEN").replace(/_/g, " ").toLowerCase();

  // Determine display scanner badge
  let displayScanner = scannerLabel(finding.scanner);
  if (finding.scanner === "SAST_LLM") displayScanner = "SAST (AI)";
  else if (finding.scanner === "SAST_PATTERN") displayScanner = "SAST (Pattern)";
  else if (finding.scanner === "SECRETS_PATTERN") displayScanner = "Secrets (Pattern)";
  else if (finding.scanner === "SECRETS_LLM") displayScanner = "Secrets (AI)";
  else if (finding.scanner === "SCA") displayScanner = "SCA";

  const isPattern =
    finding.scanner.toUpperCase().includes("PATTERN") ||
    finding.scanner === "SECRETS_PATTERN" ||
    finding.scanner === "SAST_PATTERN";

  const meta =
    finding.metadata && typeof finding.metadata === "object" && !Array.isArray(finding.metadata)
      ? (finding.metadata as Record<string, unknown>)
      : {};

  const isSca =
    finding.scanner.toUpperCase().startsWith("SCA") ||
    meta.packageName != null ||
    meta.currentVersion != null;

  const isSecret =
    finding.scanner.toUpperCase().startsWith("SECRET") ||
    meta.secretType != null;

  return `<div class="vuln-card">
    <div class="vuln-header">
      <span class="badge ${severityBadgeClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
      <span class="badge badge-scanner">${escapeHtml(displayScanner)}</span>
      ${
        finding.cweId
          ? `<a href="https://cwe.mitre.org/data/definitions/${escapeHtml(finding.cweId.replace(/^CWE-/i, ""))}.html" target="_blank" rel="noopener noreferrer" class="badge badge-cwe">${escapeHtml(finding.cweId)}</a>`
          : ""
      }
      ${
        finding.cveId
          ? `<a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(finding.cveId)}" target="_blank" rel="noopener noreferrer" class="badge badge-cve">${escapeHtml(finding.cveId)}</a>`
          : ""
      }
      ${
        finding.confidence != null
          ? `<span class="badge badge-confidence">Confidence: ${Math.round(finding.confidence * 100)}%</span>`
          : ""
      }
      <strong>${escapeHtml(report.vulnerabilityName || finding.title)}</strong>
      <span class="badge badge-status">${escapeHtml(statusLabel)}</span>
    </div>

    <div class="loc-row">
      ${location ? `<span class="loc">${escapeHtml(location)}</span>` : `<span class="loc">Location not recorded</span>`}
      <span class="loc-scanner">· ${escapeHtml(displayScanner)}</span>
    </div>

    ${
      isPattern
        ? `<div class="notice-pattern">This match comes from a <strong>pattern-based</strong> rule. Verify the code context to confirm reachability.</div>`
        : ""
    }

    ${
      finding.snippet
        ? `<div class="evidence-box">
             <div class="evidence-header">Code Evidence</div>
             <pre class="evidence-code"><code>${escapeHtml(finding.snippet)}</code></pre>
           </div>`
        : ""
    }

    ${
      isSca
        ? `<div class="sca-details-box">
             <div class="sca-grid">
               <div><span class="meta-label">Package Name</span><code class="meta-val">${escapeHtml(String(meta.packageName || finding.ruleId || "Unknown"))}</code></div>
               <div><span class="meta-label">Current Version</span><code class="meta-val">${escapeHtml(String(meta.currentVersion || "Unknown"))}</code></div>
               <div><span class="meta-label">Fixed Version</span><code class="meta-val fixed-ver">${escapeHtml(String(meta.fixVersion || "Upgrade required"))}</code></div>
             </div>
             ${
               Array.isArray(meta.usageLocations) && meta.usageLocations.length > 0
                 ? `<div class="usage-locations-box">
                      <span class="meta-label">Where Used In Source Code</span>
                      ${(meta.usageLocations as Array<{ filePath: string; line: number; usage: string }>).map((loc) => `
                        <div class="usage-item">
                          <span class="usage-file">${escapeHtml(loc.filePath)}:${loc.line}</span>
                          <pre class="usage-code"><code>${escapeHtml(loc.usage)}</code></pre>
                        </div>
                      `).join("")}
                    </div>`
                 : ""
             }
           </div>`
        : ""
    }

    ${
      isSecret
        ? `<div class="secret-details-box">
             <span class="meta-label">Secrets Identified</span>
             <div class="secret-row">
               <span class="secret-type-badge">${escapeHtml(String(meta.secretType || "Secret Credential"))}</span>
               <code class="secret-mask">****</code>
             </div>
             <p class="secret-warning">This secret was found in source code or repository configuration. Rotate and revoke immediately.</p>
           </div>`
        : ""
    }

    <div class="field">
      <span class="label">Summary</span>
      <div class="body">${formatSummaryHtml(report.summary || "N/A")}</div>
    </div>
    ${renderReproductionFields(report.stepsToReproduce)}
    <div class="field">
      <span class="label">Impact</span>
      <div class="body">${escapeHtml(report.impact || "N/A")}</div>
    </div>
    ${renderRemediationFields(report.remediation)}
  </div>`;
}

function renderReproductionFields(items: string[]): string {
  const steps = normalizeReproductionSteps(items);
  if (steps.length === 0) return "";
  const body = steps
    .map((rawStep, index) => {
      // Strip leading numbering
      const cleanStep = rawStep
        .replace(/^\s*\d+[\.):]\s*/, "")
        .replace(/^\s*\d+\s+(?=[A-Za-z])/, "");

      // Check for code blocks
      const codeMatch = cleanStep.match(/`{2,3}[\w-]*\n?([\s\S]*?)`{2,3}/);
      const isPlainCmd =
        !codeMatch &&
        (cleanStep.startsWith("curl ") ||
          cleanStep.startsWith("http://") ||
          cleanStep.startsWith("https://") ||
          cleanStep.startsWith("graphql "));

      const textPart = codeMatch
        ? cleanStep.replace(/`{2,3}[\w-]*\n?[\s\S]*?`{2,3}/, "").trim()
        : isPlainCmd
          ? ""
          : cleanStep;

      const codePart = codeMatch
        ? codeMatch[1].trim()
        : isPlainCmd
          ? cleanStep.trim()
          : null;

      return `<div class="repro-step">
        <div class="step-tag">Step ${index + 1}</div>
        <div class="body">${textPart ? escapeHtml(textPart) : ""}${
          codePart ? `<pre class="code-block"><code>${escapeHtml(codePart)}</code></pre>` : ""
        }</div>
      </div>`;
    })
    .join("");
  return `<div class="field">
    <span class="label">Steps to reproduce</span>
    <div class="repro-steps">${body}</div>
  </div>`;
}

function renderRemediationFields(items: string[]): string {
  if (!items.length) return "";
  const lis = items.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
  return `<div class="field">
    <span class="label">Remediation</span>
    <ol class="remed">${lis}</ol>
  </div>`;
}

/** Expand combined blobs into discrete steps and render as Step 1, Step 2, … */
function normalizeReproductionSteps(items: string[]): string[] {
  const trimmed = items
    .map((s) => (typeof s === "string" ? s.trim() : ""))
    .filter(Boolean);
  if (trimmed.length === 0) return [];

  const merged = trimmed.join("\n");

  let chunks: string[] = merged.split(/\n(?=\s*(?:\d+[\.)]\s|[-*•]\s))/);
  if (chunks.length <= 1) {
    chunks = merged.split(/\n\n+/).map((s) => s.trim()).filter(Boolean);
  }
  if (chunks.length <= 1 && merged.includes("\n")) {
    chunks = merged.split("\n").map((s) => s.trim()).filter(Boolean);
  }
  if (chunks.length <= 1) {
    chunks = [merged];
  }

  const stripMarkers = (s: string) =>
    s.replace(/^\s*(?:\d+[\.)]\s*|[-*•]\s*)/, "").trim();

  let steps = chunks.map(stripMarkers).filter(Boolean);
  if (steps.length === 0) steps = trimmed;

  const single = steps[0];
  if (
    steps.length === 1 &&
    single.length > 320 &&
    !single.includes("\n") &&
    /[.!?]\s+\S/.test(single)
  ) {
    const sentences = single
      .split(/(?<=[.!?])\s+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 20);
    if (sentences.length >= 2) return sentences.slice(0, 14);
  }

  return steps;
}

function readStoredReport(metadata: unknown, finding?: ReportFinding): StoredReport | undefined {
  const data =
    metadata && typeof metadata === "object" && !Array.isArray(metadata)
      ? (metadata as Record<string, unknown>)
      : {};
  const value = (data.reportSections || data.generatedDetails) as Record<string, unknown> | undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const vulnName =
    (typeof value.vulnerabilityName === "string" && value.vulnerabilityName) ||
    (typeof value.title === "string" && value.title) ||
    finding?.title ||
    "";
  const summary =
    (typeof value.summary === "string" && value.summary) ||
    (typeof value.vulnerabilityDetails === "string" && value.vulnerabilityDetails) ||
    "";
  const impact = typeof value.impact === "string" ? value.impact : "";
  const stepsToReproduce = Array.isArray(value.stepsToReproduce)
    ? value.stepsToReproduce.filter((step): step is string => typeof step === "string")
    : typeof value.stepsToReproduce === "string"
      ? [value.stepsToReproduce]
      : [];
  const remediation = Array.isArray(value.remediation)
    ? value.remediation.filter((step): step is string => typeof step === "string")
    : typeof value.remediation === "string"
      ? [value.remediation]
      : [];

  if (!vulnName && !summary && !impact && remediation.length === 0) {
    return undefined;
  }

  return {
    vulnerabilityName: vulnName,
    summary,
    stepsToReproduce,
    impact,
    remediation,
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

