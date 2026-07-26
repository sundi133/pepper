import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  enrichFindingWithReport,
  findingHasStoredReport,
} from "@/lib/finding-report";

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

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: { id: true },
  });
  if (!scan) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  }

  const { searchParams } = new URL(req.url);
  const severity = searchParams.get("severity")?.split(",");
  const scanner = searchParams.get("scanner")?.split(",");
  const filePath = searchParams.get("filePath");
  const status = searchParams.get("status")?.split(",");
  const isNewParam = searchParams.get("isNew");
  const page = Math.max(1, parseInt(searchParams.get("page") || "1"));
  const limit = Math.min(
    500,
    Math.max(1, parseInt(searchParams.get("limit") || "50")),
  );
  const sort = searchParams.get("sort") || "severity";

  const where: Record<string, unknown> = { scanId };
  if (severity) where.severity = { in: severity };
  if (scanner) where.scanner = { in: scanner };
  if (filePath) where.filePath = { contains: filePath };
  if (status) where.status = { in: status };
  if (isNewParam === "true") where.isNew = true;
  else if (isNewParam === "false") where.isNew = false;

  // Exclude INFO severity findings from UI (INFO is internal categorization only)
  // Valid UI severities: CRITICAL, HIGH, MEDIUM, LOW
  if (!severity) {
    where.severity = { notIn: ["INFO"] };
  }

  // Everything except the scanner filter, for the per-scanner totals.
  const countsWhere = { ...where };
  delete (countsWhere as Record<string, unknown>).scanner;

  const orderBy: Record<string, string> = {};
  if (sort === "risk") {
    orderBy.riskScore = "desc"; // highest risk first
  } else if (sort === "severity") {
    orderBy.severity = "asc"; // CRITICAL first (enum ordering)
  } else if (sort === "file") {
    orderBy.filePath = "asc";
  } else {
    orderBy.createdAt = "desc";
  }

  // Counts are aggregated over every matching finding, not the returned page.
  // Deriving them from the page made a whole scanner's tab disappear once the
  // results ran past the limit: with severity sorting, 400+ criticals filled the
  // page and lower-severity SCA findings fell outside it entirely.
  const [findings, total, byScanner] = await Promise.all([
    prisma.finding.findMany({
      where,
      orderBy,
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.finding.count({ where }),
    // Counts deliberately ignore the scanner filter: the tab strip must keep
    // showing every category even while one of them is selected, otherwise
    // choosing a tab would hide all the others.
    prisma.finding.groupBy({
      by: ["scanner"],
      where: countsWhere,
      _count: { _all: true },
    }),
  ]);

  const scannerCounts: Record<string, number> = {};
  for (const row of byScanner) {
    scannerCounts[row.scanner] = row._count._all;
  }

  const enrichedFindings = findings.map(enrichFindingWithReport);
  await Promise.allSettled(
    enrichedFindings
      .filter((finding, index) => !findingHasStoredReport(findings[index]))
      .map((finding) =>
        prisma.finding.update({
          where: { id: finding.id },
          data: { metadata: finding.metadata as object },
        }),
      ),
  );

  return NextResponse.json({
    findings: enrichedFindings,
    /** Totals per scanner across all matching findings, for the section tabs. */
    scannerCounts,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}
