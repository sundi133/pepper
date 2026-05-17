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
      project: { select: { name: true, repoUrl: true } },
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

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(`Security Report — ${projectName}`)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1a1a2e; background: #f8f9fa; padding: 2rem; }
    .container { max-width: 900px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); padding: 2rem; }
    h1 { color: #1a1a2e; border-bottom: 3px solid #6366f1; padding-bottom: 0.5rem; margin-bottom: 1rem; font-size: 1.75rem; }
    h2 { color: #374151; margin: 1.5rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #e5e7eb; font-size: 1.25rem; }
    .meta { color: #6b7280; font-size: 0.875rem; margin-bottom: 0.35rem; }
    .meta a { color: #4f46e5; word-break: break-all; }
    .vuln-card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 1rem; margin: 0.75rem 0; }
    .vuln-header { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
    .vuln-header strong { flex: 1 1 200px; min-width: 0; }
    .badge { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .badge-sev-critical { background: #fee2e2; color: #dc2626; }
    .badge-sev-high { background: #ffedd5; color: #ea580c; }
    .badge-sev-medium { background: #fef3c7; color: #d97706; }
    .badge-sev-low { background: #d1fae5; color: #059669; }
    .badge-sev-info { background: #dbeafe; color: #2563eb; }
    .badge-status { background: #e5e7eb; color: #374151; text-transform: none; font-weight: 500; }
    .loc { color: #6b7280; font-size: 0.875rem; margin-bottom: 0.75rem; }
    .field { margin-bottom: 0.75rem; }
    .field .label { font-weight: 600; color: #374151; display: block; margin-bottom: 0.25rem; }
    .field .body { color: #4b5563; font-size: 0.9rem; white-space: pre-wrap; overflow-wrap: anywhere; }
    .repro-steps { margin-top: 0.35rem; }
    .repro-step { margin-top: 0.65rem; padding-top: 0.65rem; border-top: 1px solid #e5e7eb; }
    .repro-step:first-child { margin-top: 0; padding-top: 0; border-top: none; }
    .repro-step .step-tag { font-weight: 700; color: #4338ca; font-size: 0.85rem; margin-bottom: 0.2rem; }
    ol.remed { margin: 0.35rem 0 0 1.1rem; padding-left: 0.5rem; color: #4b5563; font-size: 0.9rem; }
    ol.remed li { margin-top: 0.35rem; }
    .empty { text-align: center; color: #6b7280; padding: 2rem; }
    .footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #e5e7eb; text-align: center; color: #6b7280; font-size: 0.875rem; }
    @media print { body { background: #fff; padding: 0; } .container { box-shadow: none; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>Security Report</h1>
    <p class="meta"><strong>Project:</strong> ${escapeHtml(projectName)}</p>
    ${
      repoUrl
        ? `<p class="meta"><strong>Repository:</strong> <a href="${escapeHtml(repoUrl)}" rel="noopener noreferrer">${escapeHtml(repoDisplay)}</a></p>`
        : repoDisplay
          ? `<p class="meta"><strong>Repository:</strong> ${escapeHtml(repoDisplay)}</p>`
          : ""
    }
    <p class="meta"><strong>Last scan:</strong> ${escapeHtml(formatDate(lastScanAt))}</p>
    <p class="meta"><strong>Source:</strong> ${escapeHtml(sourceLine)} · Gate ${escapeHtml(scan.gateResult)} · ${escapeHtml(scan.status)}</p>

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

function renderVulnCard(finding: ReportFinding): string {
  const report = readStoredReport(finding.metadata) || fallbackReport(finding);
  const location = formatLocation(finding);
  const statusLabel = (finding.status || "OPEN").replace(/_/g, " ").toLowerCase();
  const scanner = scannerLabel(finding.scanner);

  return `<div class="vuln-card">
    <div class="vuln-header">
      <span class="badge ${severityBadgeClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
      <strong>${escapeHtml(report.vulnerabilityName || finding.title)}</strong>
      <span class="badge badge-status">${escapeHtml(statusLabel)}</span>
    </div>
    <p class="loc">${location ? `${escapeHtml(location)}` : "Location not recorded"} · ${escapeHtml(scanner)}</p>
    <div class="field">
      <span class="label">Summary</span>
      <div class="body">${escapeHtml(report.summary || "N/A")}</div>
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
    .map(
      (text, index) => `<div class="repro-step">
        <div class="step-tag">Step ${index + 1}</div>
        <div class="body">${escapeHtml(text)}</div>
      </div>`,
    )
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
