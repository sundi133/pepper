import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getActiveOrgId } from "@/lib/auth-guard";
import { enrichFindingWithReport } from "@/lib/finding-report";
import { orgFindingsWhere } from "@/lib/scan-queries";

/**
 * Vulnerabilities workspace: every finding across the org's projects, taken
 * from the LATEST completed scan per project (so re-scans of the same repo are
 * deduplicated to the current state), filterable by severity/scanner/status/
 * repository and searchable. Org-scoped to the active org.
 */
export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { searchParams } = new URL(req.url);
  const severity = searchParams.get("severity")?.split(",").filter(Boolean);
  const scanner = searchParams.get("scanner")?.split(",").filter(Boolean);
  const status = searchParams.get("status")?.split(",").filter(Boolean);
  const projectId = searchParams.get("projectId") || undefined;
  const q = searchParams.get("q")?.trim().slice(0, 200) || undefined;
  const includeFalsePositives =
    searchParams.get("includeFalsePositives") === "true";
  const page = Math.max(1, parseInt(searchParams.get("page") || "1"));
  const limit = Math.min(200, Math.max(1, parseInt(searchParams.get("limit") || "50")));
  const sort = searchParams.get("sort") || "risk";

  // The current state of each project = its latest COMPLETED scan. distinct on
  // projectId with createdAt desc keeps the newest scan per project.
  const latestScans = await prisma.scan.findMany({
    where: {
      project: { organizationId: orgId },
      status: "COMPLETED",
      ...(projectId ? { projectId } : {}),
    },
    orderBy: [{ projectId: "asc" }, { createdAt: "desc" }],
    distinct: ["projectId"],
    select: {
      id: true,
      projectId: true,
      createdAt: true,
      project: { select: { id: true, name: true } },
    },
  });

  // Repository filter list (every project with a completed scan), for the UI.
  const projects = latestScans
    .map((s) => ({ id: s.projectId, name: s.project.name, scanId: s.id }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const scanIds = latestScans.map((s) => s.id);
  if (scanIds.length === 0) {
    return NextResponse.json({
      findings: [],
      scannerCounts: {},
      severityCounts: {},
      projects,
      pagination: { page, limit, total: 0, totalPages: 0 },
    });
  }

  const where = orgFindingsWhere({
    scanIds,
    severity,
    scanner,
    status,
    includeFalsePositives,
    q,
  });

  // Severity/scanner counts ignore their own filter so the summary and tabs keep
  // showing every bucket while one is selected.
  const severityCountsWhere = { ...where };
  delete (severityCountsWhere as Record<string, unknown>).severity;
  const scannerCountsWhere = { ...where };
  delete (scannerCountsWhere as Record<string, unknown>).scanner;

  const orderBy =
    sort === "severity"
      ? { severity: "asc" as const }
      : sort === "recent"
        ? { createdAt: "desc" as const }
        : { riskScore: "desc" as const };

  const [rows, total, byScanner, bySeverity] = await Promise.all([
    prisma.finding.findMany({
      where,
      orderBy,
      skip: (page - 1) * limit,
      take: limit,
      include: {
        scan: {
          select: { id: true, projectId: true, project: { select: { name: true } } },
        },
      },
    }),
    prisma.finding.count({ where }),
    prisma.finding.groupBy({
      by: ["scanner"],
      where: scannerCountsWhere,
      _count: { _all: true },
    }),
    prisma.finding.groupBy({
      by: ["severity"],
      where: severityCountsWhere,
      _count: { _all: true },
    }),
  ]);

  const findings = rows.map((f) => ({
    ...enrichFindingWithReport(f),
    projectId: f.scan.projectId,
    projectName: f.scan.project.name,
    scanId: f.scanId,
  }));

  const scannerCounts: Record<string, number> = {};
  for (const r of byScanner) scannerCounts[r.scanner] = r._count._all;
  const severityCounts: Record<string, number> = {};
  for (const r of bySeverity) severityCounts[r.severity] = r._count._all;

  return NextResponse.json({
    findings,
    scannerCounts,
    severityCounts,
    projects,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}
