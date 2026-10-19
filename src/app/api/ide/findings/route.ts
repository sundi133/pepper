import { NextRequest, NextResponse } from "next/server";
import { verifyApiKey } from "@/lib/api-key";
import { prisma } from "@/lib/prisma";
import type { Prisma } from "@/generated/prisma/client";

/**
 * IDE-facing endpoint that returns the latest findings for a given repository
 * (and optional file path / severity filter), authenticated with an API key.
 * Used by the Pepper language server (ide/pepper-lsp, docs/IDE_EXTENSION_SPEC.md §4.2).
 *
 * GET /api/ide/findings?repositoryId=...&branch=main&filePath=...&minSeverity=HIGH
 *
 * `projectId` is accepted for `repositoryId`. With `branch`, the latest
 * completed scan of that branch is used when there is one. Findings triaged as
 * false positive, accepted risk or resolved are left out unless
 * `includeTriaged=true` (false positives are always left out).
 */
const SEV_RANK: Record<string, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const MAX_FINDINGS = 500;

function webBaseUrl(): string | null {
  const base = process.env.NEXTAUTH_URL || process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL;
  return base ? base.replace(/\/+$/, "") : null;
}

const text = (v: unknown) => (typeof v === "string" && v.trim() ? v : null);

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req.headers.get("authorization"));
  if (!auth) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const url = new URL(req.url);
  const projectId = url.searchParams.get("repositoryId") || url.searchParams.get("projectId");
  const filePath = url.searchParams.get("filePath");
  const branch = url.searchParams.get("branch")?.trim() || null;
  const includeTriaged = url.searchParams.get("includeTriaged") === "true";
  const minSev = (url.searchParams.get("minSeverity") || "INFO").toUpperCase();
  if (!projectId) {
    return NextResponse.json({ error: "repositoryId is required" }, { status: 400 });
  }

  const project = await prisma.project.findFirst({
    where: { id: projectId, organizationId: auth.organizationId },
    select: { id: true, name: true },
  });
  if (!project) {
    return NextResponse.json({ error: "Project not found" }, { status: 404 });
  }

  const scanSelect = { id: true, completedAt: true, commitSha: true, branch: true } as const;
  const scanWhere = { projectId, status: "COMPLETED" as const, project: { organizationId: auth.organizationId } };
  const latestScan =
    (branch
      ? await prisma.scan.findFirst({ where: { ...scanWhere, branch }, orderBy: { completedAt: "desc" }, select: scanSelect })
      : null) ??
    (await prisma.scan.findFirst({ where: scanWhere, orderBy: { completedAt: "desc" }, select: scanSelect }));
  if (!latestScan) {
    return NextResponse.json({ scan: null, findings: [] });
  }

  const minRank = SEV_RANK[minSev] ?? 0;
  const statuses: Prisma.FindingWhereInput["status"] = includeTriaged
    ? { not: "FALSE_POSITIVE" }
    : { in: ["OPEN", "IN_PROGRESS"] };
  const findings = await prisma.finding.findMany({
    where: {
      scanId: latestScan.id,
      status: statuses,
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
      snippet: true,
      riskScore: true,
      metadata: true,
    },
    orderBy: [{ riskScore: { sort: "desc", nulls: "last" } }, { id: "asc" }],
    take: MAX_FINDINGS + 1,
  });

  const base = webBaseUrl();
  const filtered = findings
    .slice(0, MAX_FINDINGS)
    .filter((f) => (SEV_RANK[f.severity] ?? 0) >= minRank)
    .map(({ metadata, ...f }) => {
      const m = (metadata && typeof metadata === "object" ? metadata : {}) as Record<string, unknown>;
      return {
        ...f,
        remediation: text(m.remediation) ?? text(m.fix),
        attackPath: text(m.attackPath) ?? text(m.whyExploitable),
        validation: text(m.validation),
        url: base ? `${base}/scans/${latestScan.id}` : null,
      };
    });

  return NextResponse.json({
    project,
    scan: latestScan,
    findings: filtered,
    truncated: findings.length > MAX_FINDINGS,
    webBaseUrl: base,
  });
}
