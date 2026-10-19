import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requireAuth, requireRole, getDefaultOrgId } from "@/lib/auth-guard";
import { MAX_FINDINGS_PER_RUN } from "@/lib/remediation/types";
import { startRemediationRun } from "@/lib/remediation/start-run";

const bodySchema = z.object({
  findingIds: z.array(z.string().min(1).max(64)).min(1).max(MAX_FINDINGS_PER_RUN),
});

/**
 * POST /api/scans/[scanId]/remediation — start an AI remediation run for the
 * selected findings. The run executes in the worker; follow it via
 * /api/remediation/runs/[runId]/stream.
 */
export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const role = await requireRole(orgId, "DEVELOPER");
  if ("error" in role) return role.error;

  const { scanId } = await params;
  const parsed = bodySchema.safeParse(await req.json().catch(() => ({})));
  if (!parsed.success) {
    return NextResponse.json(
      { error: `Select between 1 and ${MAX_FINDINGS_PER_RUN} findings to remediate.` },
      { status: 400 },
    );
  }
  const result = await startRemediationRun({
    organizationId: orgId,
    userId: auth.session.user.id,
    scanId,
    findingIds: parsed.data.findingIds,
  });
  if (!result.ok) {
    return NextResponse.json(
      { error: result.error, ...(result.code ? { code: result.code } : {}), ...(result.runId ? { runId: result.runId } : {}) },
      { status: result.status },
    );
  }

  return NextResponse.json({ runId: result.runId }, { status: 201 });
}

/** GET /api/scans/[scanId]/remediation — recent runs for this scan's repository. */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const { scanId } = await params;
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: { projectId: true },
  });
  if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });
  // Runs started from this scan, plus any run still working on the repository
  // (so it can be watched from a newer scan). A finished run from an earlier
  // scan is not shown here: on a fresh rescan it reads as that scan's result.
  const runs = await prisma.remediationRun.findMany({
    where: {
      organizationId: orgId,
      OR: [{ scanId }, { projectId: scan.projectId, status: { in: ["QUEUED", "RUNNING"] } }],
    },
    orderBy: { createdAt: "desc" },
    take: 10,
    select: {
      id: true,
      status: true,
      prUrl: true,
      fixedCount: true,
      failedCount: true,
      errorMessage: true,
      createdAt: true,
      completedAt: true,
      _count: { select: { items: true } },
    },
  });
  return NextResponse.json({
    runs: runs.map(({ _count, ...r }) => ({ ...r, total: _count.items })),
  });
}
