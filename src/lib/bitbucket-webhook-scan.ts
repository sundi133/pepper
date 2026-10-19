import { prisma } from "@/lib/prisma";
import { scanQueue, type ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { ensureWebhookScanSlot } from "@/lib/webhook-scan-slot";
import { normalizeBitbucketUuid } from "@/lib/parse-bitbucket-repo-input";
import { mainBranchWebhookScanType } from "@/lib/github-webhook-scan";

export type BitbucketWebhookProject = NonNullable<
  Awaited<ReturnType<typeof findProjectForBitbucketWebhook>>
>;

const include = {
  buildGate: true,
  organization: { include: { settings: true } },
} as const;

/** `workspace/slug` of a stored repository URL, lower-cased, without `.git`. */
function repoPathOf(repoUrl: string | null): string | null {
  const raw = repoUrl?.trim();
  if (!raw) return null;
  const scp = /^[^@\s/]+@[^:\s/]+:(?!\/)(.+)$/.exec(raw);
  let path: string;
  if (scp) path = scp[1];
  else {
    try {
      path = decodeURIComponent(new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`).pathname);
    } catch {
      return null;
    }
  }
  return path.replace(/^\/+|\/+$/g, "").replace(/\.git$/i, "").toLowerCase();
}

/**
 * The project a Bitbucket event is for: by repository UUID first, then by an
 * exact match of `workspace/slug` on the stored URL (`acme/api` never matches
 * `acme/api-legacy`).
 */
export async function findProjectForBitbucketWebhook(params: {
  fullName: string;
  repoUuid?: string | null;
  organizationId?: string | null;
}) {
  const slug = params.fullName?.trim();
  if (!slug) return null;
  const org = params.organizationId ? { organizationId: params.organizationId } : {};

  const repoUuid = params.repoUuid?.trim();
  const normalizedUuid = repoUuid ? normalizeBitbucketUuid(repoUuid) : null;
  if (normalizedUuid) {
    const byUuid = await prisma.project.findFirst({ where: { bitbucketRepoUuid: normalizedUuid, ...org }, include });
    if (byUuid) return byUuid;
  }

  const wanted = slug.toLowerCase();
  const candidates = await prisma.project.findMany({
    where: { repoUrl: { contains: slug, mode: "insensitive" }, ...org },
    include,
    orderBy: { createdAt: "asc" },
    take: 50,
  });
  return candidates.find((p) => repoPathOf(p.repoUrl) === wanted) ?? null;
}

/** True when a push targets the project's default branch (e.g. main). */
export function isBitbucketPushToDefaultBranch(params: {
  branchName: string;
  defaultBranch: string;
}): boolean {
  const branch = params.branchName?.trim();
  if (!branch) return false;
  return branch === (params.defaultBranch?.trim() || "main");
}

export async function queueBitbucketWebhookScan(params: {
  project: BitbucketWebhookProject;
  scanType: ScanJobData["scanType"];
  repoUrl: string;
  branch: string;
  commitSha?: string;
  baseSha?: string;
  prNumber?: number;
  /** .pepper.yaml paths.exclude */
  pathExcludes?: string[];
}): Promise<{ scanId: string; status: "QUEUED" | "ALREADY_QUEUED" }> {
  const commitSha = params.commitSha?.trim();
  const slot = await ensureWebhookScanSlot({
    projectId: params.project.id,
    commitSha,
    scanType: params.scanType,
    prNumber: params.prNumber,
    branch: params.branch,
  });
  if (slot.status === "ALREADY_QUEUED") {
    return { scanId: slot.scanId, status: "ALREADY_QUEUED" };
  }

  const settings = params.project.organization.settings;

  const scan = await prisma.scan.create({
    data: {
      projectId: params.project.id,
      scanType: params.scanType,
      sourceType: "WEBHOOK",
      sourceRef: params.repoUrl,
      branch: params.branch,
      commitSha: commitSha || undefined,
      baseSha: params.baseSha,
      prNumber: params.prNumber,
      status: "QUEUED",
    },
  });

  const jobData: ScanJobData = {
    scanId: scan.id,
    projectId: params.project.id,
    sourceType: "GIT_CLONE",
    sourceRef: params.repoUrl,
    scanType: params.scanType,
    baseSha: params.baseSha,
    commitSha: commitSha || undefined,
    prNumber: params.prNumber,
    repoUrl: params.repoUrl,
    branch: params.branch,
    // Webhook scans always ask for the connection; the worker sends tokens
    // only to bitbucket.org (docs/PR_REVIEW_PROVIDERS_SPEC.md §3.3).
    useOrgBitbucketToken: true,
    ...(params.pathExcludes?.length ? { pathExcludes: params.pathExcludes } : {}),
    orgSettings: buildOrgSettingsForJob(
      settings,
      params.project.organizationId,
    ),
    buildGate: params.project.buildGate
      ? {
          maxCritical: params.project.buildGate.maxCritical,
          maxHigh: params.project.buildGate.maxHigh,
          maxMedium: params.project.buildGate.maxMedium,
          maxLow: params.project.buildGate.maxLow,
          failOnNew: params.project.buildGate.failOnNew,
        }
      : undefined,
  };

  const job = await scanQueue.add("scan", jobData, { jobId: scan.id });
  await prisma.scan.update({
    where: { id: scan.id },
    data: { jobId: job.id },
  });

  return { scanId: scan.id, status: "QUEUED" };
}
export { mainBranchWebhookScanType };

