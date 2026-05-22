import { prisma } from "@/lib/prisma";
import { scanQueue, type ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { ensureWebhookScanSlot } from "@/lib/webhook-scan-slot";

export type GithubWebhookProject = Awaited<
  ReturnType<typeof findProjectForGithubWebhook>
>;

export function githubRefToBranch(ref: string): string | null {
  if (!ref?.startsWith("refs/heads/")) return null;
  return ref.slice("refs/heads/".length);
}

/** True when a push ref targets the project's default branch (e.g. main). */
export function isPushToDefaultBranch(params: {
  ref: string;
  defaultBranch: string;
}): boolean {
  const branch = githubRefToBranch(params.ref);
  if (!branch) return false;
  return branch === (params.defaultBranch?.trim() || "main");
}

export function isMergedPullRequestToDefaultBranch(params: {
  merged: boolean;
  baseRef: string;
  defaultBranch: string;
}): boolean {
  if (!params.merged) return false;
  const base = params.baseRef?.trim() || "main";
  return base === (params.defaultBranch?.trim() || "main");
}

/** Scan type queued after code lands on the default branch (merge or direct push). */
export function mainBranchWebhookScanType(): ScanJobData["scanType"] {
  const raw = process.env.GITHUB_WEBHOOK_MAIN_SCAN_TYPE?.trim().toUpperCase();
  if (raw === "FULL" || raw === "INCREMENTAL" || raw === "SAST_ONLY") {
    return raw;
  }
  return "SAST_ONLY";
}

export async function findProjectForGithubWebhook(fullName: string) {
  const slug = fullName?.trim();
  if (!slug) return null;

  return prisma.project.findFirst({
    where: { repoUrl: { contains: slug } },
    include: {
      buildGate: true,
      organization: { include: { settings: true } },
    },
  });
}

export async function queueGithubWebhookScan(params: {
  project: NonNullable<GithubWebhookProject>;
  scanType: ScanJobData["scanType"];
  repoUrl: string;
  branch: string;
  commitSha?: string;
  baseSha?: string;
  prNumber?: number;
}): Promise<{ scanId: string; status: "QUEUED" | "ALREADY_QUEUED" }> {
  const commitSha = params.commitSha?.trim();
  const slot = await ensureWebhookScanSlot({
    projectId: params.project.id,
    commitSha,
    scanType: params.scanType,
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
    useOrgGithubToken: params.project.connectedViaGithub,
    orgSettings: buildOrgSettingsForJob(
      settings,
      params.project.organizationId,
    ),
    dastTargetUrl: params.project.dastTargetUrl || undefined,
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
