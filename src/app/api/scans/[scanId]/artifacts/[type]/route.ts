import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { getDefaultOrgId, requireAuth } from "@/lib/auth-guard";
import { downloadObject } from "@/lib/minio";
import { buildHtmlFindingsReport } from "@/scanners/html-report-builder";
import { buildScanMarkdownReport } from "@/scanners/reports/scan-markdown-report-builder";
import type { RawFinding } from "@/scanners/types";

type ArtifactKind =
  | "SARIF"
  | "SBOM_CYCLONEDX"
  | "SCAN_LOG"
  | "HTML_FINDINGS_REPORT"
  | "MARKDOWN_FINDINGS_REPORT";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string; type: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId, type } = await params;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const requestedType = type.toLowerCase();
  const typeMap: Record<string, ArtifactKind> = {
    sarif: "SARIF",
    json: "SARIF",
    sbom: "SBOM_CYCLONEDX",
    log: "SCAN_LOG",
    html: "HTML_FINDINGS_REPORT",
    report: "HTML_FINDINGS_REPORT",
    markdown: "MARKDOWN_FINDINGS_REPORT",
    md: "MARKDOWN_FINDINGS_REPORT",
  };

  const artifactType = typeMap[requestedType];
  if (!artifactType) {
    return NextResponse.json(
      { error: "Invalid artifact type. Use: sarif, json, sbom, log, html, report, markdown, or md" },
      { status: 400 },
    );
  }

  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      project: { select: { name: true, repoUrl: true, organizationId: true } },
      findings: true,
    },
  });

  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }
  if (scan.project.organizationId !== orgId) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const artifact = await prisma.scanArtifact.findUnique({
    where: {
      scanId_type: {
        scanId,
        type: artifactType,
      },
    },
  });

  if (
    !artifact &&
    artifactType !== "HTML_FINDINGS_REPORT" &&
    artifactType !== "MARKDOWN_FINDINGS_REPORT"
  ) {
    return NextResponse.json({ error: "Artifact not found" }, { status: 404 });
  }

  const reportFindings = preferAiSastFindings(scan.findings.map(dbFindingToRawFinding));

  if (artifactType === "HTML_FINDINGS_REPORT") {
    const html = buildHtmlFindingsReport({
      scan: {
        id: scan.id,
        scanType: scan.scanType,
        branch: scan.branch,
        commitSha: scan.commitSha,
        sourceType: scan.sourceType,
        sourceRef: scan.sourceRef,
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
        filesScanned: scan.filesScanned,
        depsScanned: scan.depsScanned,
        gateResult: scan.gateResult,
      },
      project: {
        name: scan.project.name,
        repoUrl: scan.project.repoUrl,
      },
      findings: reportFindings,
    });

    return new NextResponse(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Disposition": 'inline; filename="findings-report.html"',
      },
    });
  }

  if (artifactType === "MARKDOWN_FINDINGS_REPORT") {
    const markdown = buildScanMarkdownReport({
      scan: {
        id: scan.id,
        scanType: scan.scanType,
        branch: scan.branch,
        commitSha: scan.commitSha,
        sourceType: scan.sourceType,
        sourceRef: scan.sourceRef,
      },
      project: {
        name: scan.project.name,
        repoUrl: scan.project.repoUrl,
      },
      findings: reportFindings,
    });

    return new NextResponse(markdown, {
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": 'attachment; filename="findings-report.md"',
      },
    });
  }

  try {
    const data = await downloadObject(artifact!.objectKey);
    const meta = responseMeta(artifactType, requestedType);

    return new NextResponse(new Uint8Array(data), {
      headers: {
        "Content-Type": meta.contentType,
        "Content-Disposition": `${meta.disposition}; filename="${meta.filename}"`,
      },
    });
  } catch {
    return NextResponse.json(
      { error: "Failed to download artifact" },
      { status: 500 },
    );
  }
}

function preferAiSastFindings(findings: RawFinding[]): RawFinding[] {
  const hasAiSast = findings.some((finding) => finding.scanner === "SAST_LLM");
  if (!hasAiSast) return findings;
  return findings.filter((finding) => finding.scanner !== "SAST_PATTERN");
}

function responseMeta(
  artifactType: ArtifactKind,
  requestedType: string,
): { contentType: string; filename: string; disposition: "attachment" | "inline" } {
  if (artifactType === "HTML_FINDINGS_REPORT") {
    return {
      contentType: "text/html; charset=utf-8",
      filename: "findings-report.html",
      disposition: "inline",
    };
  }
  if (artifactType === "SCAN_LOG") {
    return {
      contentType: "text/plain; charset=utf-8",
      filename: "scan.log",
      disposition: "attachment",
    };
  }
  if (artifactType === "SBOM_CYCLONEDX") {
    return {
      contentType: "application/json",
      filename: "sbom.cyclonedx.json",
      disposition: "attachment",
    };
  }
  if (artifactType === "MARKDOWN_FINDINGS_REPORT") {
    return {
      contentType: "text/markdown; charset=utf-8",
      filename: "findings-report.md",
      disposition: "attachment",
    };
  }
  return {
    contentType: "application/json",
    filename: requestedType === "json" ? "findings.sarif.json" : "results.sarif.json",
    disposition: "attachment",
  };
}

function dbFindingToRawFinding(finding: {
  scanner: string;
  severity: string;
  title: string;
  description: string;
  filePath: string | null;
  startLine: number | null;
  endLine: number | null;
  snippet: string | null;
  ruleId: string | null;
  cweId: string | null;
  cveId: string | null;
  confidence: number | null;
  metadata: unknown;
  masked: boolean;
}): RawFinding {
  return {
    scanner: finding.scanner as RawFinding["scanner"],
    severity: finding.severity as RawFinding["severity"],
    title: finding.title,
    description: finding.description,
    filePath: finding.filePath ?? undefined,
    startLine: finding.startLine ?? undefined,
    endLine: finding.endLine ?? undefined,
    snippet: finding.snippet ?? undefined,
    ruleId: finding.ruleId ?? undefined,
    cweId: finding.cweId ?? undefined,
    cveId: finding.cveId ?? undefined,
    confidence: finding.confidence ?? undefined,
    metadata:
      finding.metadata && typeof finding.metadata === "object" && !Array.isArray(finding.metadata)
        ? (finding.metadata as Record<string, unknown>)
        : undefined,
    masked: finding.masked,
  };
}
