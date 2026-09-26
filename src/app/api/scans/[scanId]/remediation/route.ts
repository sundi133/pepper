import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requireAuth, requireRole, getDefaultOrgId } from "@/lib/auth-guard";
import { getLlmConfig } from "@/lib/llm-gateway";
import { getRemediationQueue } from "@/lib/queue";
import { writeAuditLog } from "@/lib/audit-log";
import {
  loadProviderCredentials,
  missingCredentialsMessage,
  resolveRemediationRepo,
} from "@/lib/remediation/repo-target";
import { MAX_FINDINGS_PER_RUN } from "@/lib/remediation/types";

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

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
  const findingIds = [...new Set(parsed.data.findingIds)];

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: {
      id: true,
      status: true,
      sourceType: true,
      sourceRef: true,
      branch: true,
      project: {
        select: {
          repoUrl: true,
          defaultBranch: true,
          connectedViaGithub: true,
          connectedViaBitbucket: true,
          connectedViaAzure: true,
        },
      },
    },
  });
  if (!scan) return NextResponse.json({ error: "Scan not found" }, { status: 404 });

  // Fail fast on configuration problems so the user is not sent to a run
  // page that immediately fails.
  const target = resolveRemediationRepo({ scan, project: scan.project });
  if (!target.ok) {
    return NextResponse.json({ error: target.error, code: target.code }, { status: 400 });
  }
  const creds = await loadProviderCredentials(orgId, target.provider);
  if (!creds) {
    return NextResponse.json(
      { error: missingCredentialsMessage(target.provider), code: "PROVIDER_NOT_CONNECTED" },
      { status: 400 },
    );
  }
  const orgSettings = await prisma.orgSettings.findUnique({ where: { organizationId: orgId } });
  const llm = getLlmConfig(orgSettings);
  if (!llm.apiKey && llm.provider !== "ollama") {
    return NextResponse.json(
      { error: "No LLM is configured. Set a provider and API key under Settings → LLM.", code: "LLM_NOT_CONFIGURED" },
      { status: 400 },
    );
  }

  const active = await prisma.remediationRun.findFirst({
    where: { scanId, status: { in: ["QUEUED", "RUNNING"] } },
    select: { id: true },
  });
  if (active) {
    return NextResponse.json(
      { error: "A remediation run is already in progress for this scan.", runId: active.id, code: "RUN_IN_PROGRESS" },
      { status: 409 },
    );
  }

  const findings = await prisma.finding.findMany({
    where: { id: { in: findingIds }, scanId },
    select: { id: true, title: true, severity: true, filePath: true, startLine: true },
  });
  if (findings.length === 0) {
    return NextResponse.json({ error: "None of the selected findings belong to this scan." }, { status: 400 });
  }
  // Most severe first; group by file so later fixes build on earlier ones.
  findings.sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      (a.filePath ?? "").localeCompare(b.filePath ?? "") ||
      (a.startLine ?? 0) - (b.startLine ?? 0),
  );

  const run = await prisma.remediationRun.create({
    data: {
      organizationId: orgId,
      scanId,
      createdBy: auth.session.user.id,
      provider: target.provider,
      repoUrl: target.repoUrl,
      baseBranch: target.baseBranch,
      items: {
        create: findings.map((f, position) => ({
          findingId: f.id,
          position,
          title: f.title.slice(0, 500),
          severity: f.severity,
          filePath: f.filePath,
        })),
      },
    },
    select: { id: true },
  });

  try {
    await getRemediationQueue().add("remediate", { runId: run.id }, { jobId: run.id });
  } catch (e) {
    await prisma.remediationRun.update({
      where: { id: run.id },
      data: {
        status: "FAILED",
        completedAt: new Date(),
        errorMessage: `Could not queue the run: ${e instanceof Error ? e.message : String(e)}`,
      },
    });
    return NextResponse.json({ error: "Could not queue the remediation run. Is Redis reachable?" }, { status: 503 });
  }

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "remediation.started",
    resource: "scan",
    resourceId: scanId,
    details: { runId: run.id, findings: findings.length, provider: target.provider },
  }).catch(() => undefined);

  return NextResponse.json({ runId: run.id }, { status: 201 });
}

/** GET /api/scans/[scanId]/remediation — recent runs for this scan. */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });

  const { scanId } = await params;
  const runs = await prisma.remediationRun.findMany({
    where: { scanId, organizationId: orgId },
    orderBy: { createdAt: "desc" },
    take: 10,
    select: {
      id: true,
      status: true,
      prUrl: true,
      fixedCount: true,
      failedCount: true,
      createdAt: true,
      completedAt: true,
      _count: { select: { items: true } },
    },
  });
  return NextResponse.json({
    runs: runs.map(({ _count, ...r }) => ({ ...r, total: _count.items })),
  });
}
