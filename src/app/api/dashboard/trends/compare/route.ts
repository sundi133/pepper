import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { findingFingerprint } from "@/lib/fix-verification";
import { compareFindingSets, type CompareFinding } from "@/lib/scan-compare";

const LIST_LIMIT = 300;

type Version = {
  scanId: string;
  completedAt: Date;
  commitSha: string | null;
  scanType: string;
  totals: { critical: number; high: number; medium: number; low: number; info: number };
  findings: CompareFinding[] | null;
};

/**
 * Load one scan version of a project: its point-in-time finding copy, or the
 * live findings when it is the project's current scan. `findings` is null
 * when the version predates finding capture and its scan row is gone.
 */
async function loadVersion(projectId: string, scanId: string): Promise<Version | null> {
  const [snapshot, live] = await Promise.all([
    prisma.scanSnapshot.findFirst({ where: { projectId, scanId } }),
    prisma.scan.findFirst({
      where: { id: scanId, projectId, status: "COMPLETED" },
      select: {
        id: true,
        completedAt: true,
        commitSha: true,
        scanType: true,
        criticalCount: true,
        highCount: true,
        mediumCount: true,
        lowCount: true,
        infoCount: true,
      },
    }),
  ]);
  if (!snapshot && !live?.completedAt) return null;

  let findings: CompareFinding[] | null = null;
  if (snapshot?.findingsCaptured) {
    findings = await prisma.scanSnapshotFinding.findMany({
      where: { snapshotId: snapshot.id },
      select: {
        fingerprint: true,
        findingId: true,
        scanner: true,
        severity: true,
        status: true,
        title: true,
        filePath: true,
        startLine: true,
        ruleId: true,
        cweId: true,
        cveId: true,
      },
    });
  } else if (live) {
    const rows = await prisma.finding.findMany({
      where: { scanId: live.id },
      select: {
        id: true,
        scanner: true,
        severity: true,
        status: true,
        title: true,
        filePath: true,
        startLine: true,
        ruleId: true,
        cweId: true,
        cveId: true,
      },
    });
    findings = rows.map(({ id, ...r }) => ({ ...r, findingId: id, fingerprint: findingFingerprint(r) }));
  }

  if (snapshot) {
    return {
      scanId,
      completedAt: snapshot.completedAt,
      commitSha: snapshot.commitSha,
      scanType: snapshot.scanType,
      totals: {
        critical: snapshot.criticalCount,
        high: snapshot.highCount,
        medium: snapshot.mediumCount,
        low: snapshot.lowCount,
        info: snapshot.infoCount,
      },
      findings,
    };
  }
  return {
    scanId,
    completedAt: live!.completedAt!,
    commitSha: live!.commitSha,
    scanType: live!.scanType,
    totals: {
      critical: live!.criticalCount,
      high: live!.highCount,
      medium: live!.mediumCount,
      low: live!.lowCount,
      info: live!.infoCount,
    },
    findings,
  };
}

function publicFinding(f: CompareFinding) {
  return {
    title: f.title,
    severity: f.severity,
    status: f.status,
    scanner: f.scanner,
    filePath: f.filePath,
    startLine: f.startLine,
    ruleId: f.ruleId,
    cweId: f.cweId,
    cveId: f.cveId,
  };
}

/**
 * GET /api/dashboard/trends/compare?project=<id>&base=<scanId>&target=<scanId>
 *
 * Findings fixed, introduced and still present between two scan versions of a
 * repository. The older version is always treated as the base.
 */
export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const url = new URL(req.url);
  const projectId = url.searchParams.get("project")?.trim() ?? "";
  const a = url.searchParams.get("base")?.trim() ?? "";
  const b = url.searchParams.get("target")?.trim() ?? "";
  if (!projectId || !a || !b) {
    return NextResponse.json({ error: "project, base and target are required" }, { status: 400 });
  }
  if (a === b) {
    return NextResponse.json({ error: "Pick two different scans to compare." }, { status: 400 });
  }

  const project = await prisma.project.findFirst({
    where: { id: projectId, organizationId: orgId },
    select: { id: true },
  });
  if (!project) return NextResponse.json({ error: "Repository not found" }, { status: 404 });

  const [va, vb] = await Promise.all([loadVersion(projectId, a), loadVersion(projectId, b)]);
  if (!va || !vb) {
    return NextResponse.json({ error: "Scan version not found for this repository." }, { status: 404 });
  }
  const swapped = va.completedAt > vb.completedAt;
  const [base, target] = swapped ? [vb, va] : [va, vb];

  const meta = (v: Version) => ({
    scanId: v.scanId,
    completedAt: v.completedAt.toISOString(),
    commitSha: v.commitSha,
    scanType: v.scanType,
    totals: v.totals,
    findingsAvailable: v.findings !== null,
  });
  if (!base.findings || !target.findings) {
    return NextResponse.json({
      base: meta(base),
      target: meta(target),
      swapped,
      available: false,
      reason:
        "Finding details were not recorded for one of these scans (it ran before scan comparison was available). Totals are shown; scans from now on can be compared in full.",
    });
  }

  const result = compareFindingSets(base.findings, target.findings);

  // Attribute fixed findings to the AI remediation PR that fixed them.
  const fixedIds = result.fixed.map((f) => f.findingId).filter((id): id is string => !!id);
  const items = fixedIds.length
    ? await prisma.remediationItem.findMany({
        where: {
          findingId: { in: fixedIds },
          status: "FIXED",
          run: { organizationId: orgId, prUrl: { not: null } },
        },
        select: { findingId: true, run: { select: { id: true, prUrl: true, prNumber: true } } },
      })
    : [];
  const fixedBy = new Map(items.map((i) => [i.findingId, i.run]));

  return NextResponse.json({
    base: meta(base),
    target: meta(target),
    swapped,
    available: true,
    summary: {
      fixed: result.fixed.length,
      introduced: result.introduced.length,
      persisting: result.persisting.length,
      moved: result.persisting.filter((p) => p.moved).length,
      reRated: result.persisting.filter((p) => p.severityChanged).length,
      suppressed: result.suppressed,
      fixedByAi: result.fixed.filter((f) => f.findingId && fixedBy.has(f.findingId)).length,
    },
    bySeverity: result.bySeverity,
    byFile: result.byFile,
    fixed: result.fixed.slice(0, LIST_LIMIT).map((f) => ({
      ...publicFinding(f),
      fixedBy: (f.findingId && fixedBy.get(f.findingId)) || null,
    })),
    introduced: result.introduced.slice(0, LIST_LIMIT).map(publicFinding),
    persisting: result.persisting.slice(0, LIST_LIMIT).map((p) => ({
      ...publicFinding(p.target),
      previousSeverity: p.severityChanged ? p.base.severity : null,
      previousLine: p.moved ? p.base.startLine : null,
    })),
  });
}
