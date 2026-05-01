import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth } from "@/lib/auth-guard";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const { scanId } = await params;
  const { searchParams } = new URL(req.url);
  const severity = searchParams.get("severity")?.split(",");
  const scanner = searchParams.get("scanner")?.split(",");
  const filePath = searchParams.get("filePath");
  const status = searchParams.get("status")?.split(",");
  const page = parseInt(searchParams.get("page") || "1");
  const limit = parseInt(searchParams.get("limit") || "50");
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

  return NextResponse.json({
    findings,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
}
