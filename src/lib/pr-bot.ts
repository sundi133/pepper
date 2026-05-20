import { prisma } from "./prisma";
import { logger } from "./logger";
import { postScanPrSummary } from "./github-pr-comment";
import { postScanBitbucketPrSummary } from "./bitbucket-pr-comment";
import { postScanAzurePrSummary } from "./azure-devops-pr-comment";

const log = logger.child({ module: "pr-bot" });

/**
 * Dispatch a completed scan's PR-bot output to the right git provider. The
 * project's stored fields determine the platform — Pepper only ever knows
 * about one host per project. Each provider's poster is responsible for
 * its own no-op short-circuit when the scan was not webhook-triggered or
 * the org has no auth configured, so calling this for every scan is safe.
 */
export async function postScanPrReview(scanId: string): Promise<void> {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      project: {
        select: {
          githubOwner: true,
          githubRepoName: true,
          bitbucketWorkspace: true,
          bitbucketRepoSlug: true,
          azureProjectName: true,
          azureRepoId: true,
        },
      },
    },
  });

  if (!scan?.project) return;

  if (scan.project.githubOwner && scan.project.githubRepoName) {
    await postScanPrSummary(scanId);
    return;
  }

  if (scan.project.bitbucketWorkspace && scan.project.bitbucketRepoSlug) {
    await postScanBitbucketPrSummary(scanId);
    return;
  }

  if (scan.project.azureProjectName && scan.project.azureRepoId) {
    await postScanAzurePrSummary(scanId);
    return;
  }

  log.debug(
    { scanId },
    "PR review skipped: project has no recognised git provider connection",
  );
}
