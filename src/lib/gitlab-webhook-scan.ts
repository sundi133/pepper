import { prisma } from "@/lib/prisma";
import { scanQueue, type ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { ensureWebhookScanSlot } from "@/lib/webhook-scan-slot";
import { mainBranchWebhookScanType } from "@/lib/github-webhook-scan";

const include = {
  buildGate: true,
  organization: { include: { settings: true } },
} as const;

export type GitLabWebhookProject = NonNullable<
  Awaited<ReturnType<typeof findProjectForGitLabWebhook>>
>;

/**
 * `group/sub/project` of a stored repository URL, lower-cased, without `.git`.
 * Also reads `git@host:group/project.git` and URLs stored without a scheme.
 */
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
 * The project a GitLab event is for: by GitLab project id first, then by an
 * exact match of the stored URL's path (`acme/api` never matches
 * `acme/api-legacy`).
 */
export async function findProjectForGitLabWebhook(
  gitlabProjectId: number | undefined,
  pathWithNamespace: string | undefined,
  organizationId?: string | null,
  /** The connection's host URL, for self-managed GitLab under a relative root (https://host/gitlab). */
  hostUrl?: string | null,
) {
  const org = organizationId ? { organizationId } : {};
  if (typeof gitlabProjectId === "number") {
    const byId = await prisma.project.findFirst({ where: { gitlabProjectId, ...org }, include });
    if (byId) return byId;
  }
  const path = pathWithNamespace?.trim().toLowerCase();
  if (!path) return null;
  const wanted = new Set([path]);
  const root = hostUrl ? repoPathOf(hostUrl) : null;
  if (root) wanted.add(`${root}/${path}`);
  const candidates = await prisma.project.findMany({
    where: { repoUrl: { contains: path, mode: "insensitive" }, ...org },
    include,
    orderBy: { createdAt: "asc" },
    take: 50,
  });
  return candidates.find((p) => wanted.has(repoPathOf(p.repoUrl) ?? "")) ?? null;
}

export function isGitLabPushToDefaultBranch(ref: string | undefined, defaultBranch: string): boolean {
  return ref === `refs/heads/${defaultBranch?.trim() || "main"}`;
}

export async function queueGitLabWebhookScan(params: {
  project: GitLabWebhookProject;
  scanType: ScanJobData["scanType"];
  repoUrl: string;
  branch: string;
  commitSha?: string;
  baseSha?: string;
  prNumber?: number;
  /** Fork merge requests: refs/merge-requests/<iid>/head, fetched after cloning the target. */
  fetchRef?: string;
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
    // The worker uses it only when the repository is on the connection's host.
    useOrgGitLabToken: true,
    ...(params.fetchRef ? { fetchRef: params.fetchRef } : {}),
    ...(params.pathExcludes?.length ? { pathExcludes: params.pathExcludes } : {}),
    orgSettings: buildOrgSettingsForJob(params.project.organization.settings, params.project.organizationId),
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
  await prisma.scan.update({ where: { id: scan.id }, data: { jobId: job.id } });
  return { scanId: scan.id, status: "QUEUED" };
}

export { mainBranchWebhookScanType };
