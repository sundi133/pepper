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

  const orderBy: Record<string, string> = {};
  if (sort === "severity") {
    orderBy.severity = "asc"; // CRITICAL first
  } else if (sort === "file") {
    orderBy.filePath = "asc";
  } else {
    orderBy.createdAt = "desc";
  }

  const [findings, total] = await Promise.all([
    prisma.finding.findMany({
      where,
      orderBy,
      skip: (page - 1) * limit,
      take: limit,
    }),
    prisma.finding.count({ where }),
  ]);

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
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}
