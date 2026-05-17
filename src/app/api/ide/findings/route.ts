import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "@/lib/api-key";
import { prisma } from "@/lib/prisma";

/**
 * IDE-facing endpoint that returns the latest findings for a given project
 * (and optional file path / severity filter), authenticated with an API key.
 * Designed for use by VS Code / JetBrains plugins.
 *
 * GET /api/ide/findings?projectId=...&filePath=...&minSeverity=HIGH
 */
const SEV_RANK: Record<string, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req.headers.get("authorization"));
  if (!auth) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const url = new URL(req.url);
  const projectId = url.searchParams.get("projectId");
  const filePath = url.searchParams.get("filePath");
  const minSev = (url.searchParams.get("minSeverity") || "INFO").toUpperCase();
  if (!projectId) {
    return NextResponse.json({ error: "projectId is required" }, { status: 400 });
  }

  const project = await prisma.project.findFirst({
    where: { id: projectId, organizationId: auth.organizationId },
    select: { id: true, name: true },
  });
  if (!project) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  const latestScan = await prisma.scan.findFirst({
    where: { projectId, status: "COMPLETED" },
    orderBy: { completedAt: "desc" },
    select: { id: true, completedAt: true, commitSha: true, branch: true },
  });
  if (!latestScan) {
    return NextResponse.json({ scan: null, findings: [] });
  }

  const minRank = SEV_RANK[minSev] ?? 0;
  const findings = await prisma.finding.findMany({
    where: {
      scanId: latestScan.id,
      status: { not: "FALSE_POSITIVE" },
      ...(filePath ? { filePath } : {}),
    },
    select: {
      id: true,
      severity: true,
      title: true,
      description: true,
      filePath: true,
      startLine: true,
      endLine: true,
      ruleId: true,
      cveId: true,
      cweId: true,
      scanner: true,
      confidence: true,
      status: true,
    },
    take: 500,
  });

  const filtered = findings.filter(
    (f) => (SEV_RANK[f.severity] ?? 0) >= minRank,
  );

  return NextResponse.json({
    project,
    scan: latestScan,
    findings: filtered,
  });
}
