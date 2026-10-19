/**
 * Start an AI remediation run for findings of one scan: the "Fix with AI"
 * button (POST /api/scans/[scanId]/remediation) and `@pepper fix` in a pull
 * request (docs/PR_REVIEW_PROVIDERS_SPEC.md §1.5). The run executes in the
 * worker. The caller is responsible for authorization.
 */
import { prisma } from "@/lib/prisma";
import { getLlmConfig } from "@/lib/llm-gateway";
import { getRemediationQueue } from "@/lib/queue";
import { writeAuditLog } from "@/lib/audit-log";
import { credentialsMismatch, loadProviderCredentials, missingCredentialsMessage, resolveRemediationRepo } from "./repo-target";

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

export type StartRunResult =
  | { ok: true; runId: string }
  | { ok: false; status: number; error: string; code?: string; runId?: string };

export async function startRemediationRun(params: {
  organizationId: string;
  /** The Pepper user, or null when started from a pull-request comment. */
  userId: string | null;
  scanId: string;
  findingIds: string[];
  /** Extra audit detail naming where it was started (e.g. "pr-comment"). */
  via?: string;
}): Promise<StartRunResult> {
  const { organizationId: orgId, scanId } = params;
  const findingIds = [...new Set(params.findingIds)];

  const scan = await prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: {
      id: true,
      projectId: true,
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
  if (!scan) return { ok: false, status: 404, error: "Scan not found" };

  // Fail fast on configuration problems so the user is not sent to a run
  // page that immediately fails.
  const target = resolveRemediationRepo({ scan, project: scan.project });
  if (!target.ok) return { ok: false, status: 400, error: target.error, code: target.code };
  const creds = await loadProviderCredentials(orgId, target.provider, target.repoUrl);
  if (!creds) return { ok: false, status: 400, error: missingCredentialsMessage(target.provider), code: "PROVIDER_NOT_CONNECTED" };
  const mismatch = credentialsMismatch(target.repoUrl, creds);
  if (mismatch) return { ok: false, status: 400, error: mismatch, code: "PROVIDER_HOST_MISMATCH" };
  const orgSettings = await prisma.orgSettings.findUnique({ where: { organizationId: orgId } });
  const llm = getLlmConfig(orgSettings);
  if (!llm.apiKey && llm.provider !== "ollama") {
    return { ok: false, status: 400, error: "No LLM is configured. Set a provider and API key under Settings → LLM.", code: "LLM_NOT_CONFIGURED" };
  }

  const active = await prisma.remediationRun.findFirst({
    where: { scanId, status: { in: ["QUEUED", "RUNNING"] } },
    select: { id: true },
  });
  if (active) {
    return { ok: false, status: 409, error: "A remediation run is already in progress for this scan.", runId: active.id, code: "RUN_IN_PROGRESS" };
  }

  const findings = await prisma.finding.findMany({
    where: { id: { in: findingIds }, scanId },
    select: { id: true, title: true, severity: true, filePath: true, startLine: true },
  });
  if (findings.length === 0) return { ok: false, status: 400, error: "None of the selected findings belong to this scan." };
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
      projectId: scan.projectId,
      createdBy: params.userId,
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
    return { ok: false, status: 503, error: "Could not queue the remediation run. Is Redis reachable?" };
  }

  await writeAuditLog({
    organizationId: orgId,
    userId: params.userId,
    action: "remediation.started",
    resource: "scan",
    resourceId: scanId,
    details: { runId: run.id, findings: findings.length, provider: target.provider, ...(params.via ? { via: params.via } : {}) },
  }).catch(() => undefined);

  return { ok: true, runId: run.id };
}
