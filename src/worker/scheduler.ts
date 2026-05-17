import { prisma } from "@/lib/prisma";
import { scanQueue, ScanJobData } from "@/lib/queue";
import { buildOrgSettingsForJob } from "@/lib/org-settings-job";
import { computeNextRun } from "@/lib/schedule-utils";
import { logger } from "@/lib/logger";

const CHECK_INTERVAL_MS = 60_000; // Check every 60 seconds

/**
 * Scheduler loop: checks for due scan schedules and enqueues jobs.
 * Runs inside the worker process.
 */
export function startScheduler() {
  logger.info("Scan scheduler started (checking every 60s)");

  const interval = setInterval(async () => {
    try {
      await checkDueSchedules();
    } catch (err) {
      logger.error({ err }, "Scheduler tick failed");
    }
  }, CHECK_INTERVAL_MS);

  // Also run immediately on start
  checkDueSchedules().catch((err) => {
    logger.error({ err }, "Initial scheduler check failed");
  });

  return interval;
}

async function checkDueSchedules() {
  const now = new Date();

  const dueSchedules = await prisma.scanSchedule.findMany({
    where: {
      enabled: true,
      nextRunAt: { lte: now },
    },
    include: {
      project: {
        include: {
          organization: true,
          buildGate: true,
        },
      },
    },
  });

  if (dueSchedules.length === 0) return;

  logger.info({ count: dueSchedules.length }, "Found due scan schedules");

  for (const schedule of dueSchedules) {
    const project = schedule.project;

    // Project must have a repoUrl for scheduled scans
    if (!project.repoUrl) {
      logger.warn(
        { projectId: project.id, projectName: project.name },
        "Skipping scheduled scan: project has no repository URL",
      );
      // Update nextRunAt to avoid re-triggering
      await prisma.scanSchedule.update({
        where: { id: schedule.id },
        data: {
          lastRunAt: now,
          nextRunAt: computeNextRun(schedule.frequency),
        },
      });
      continue;
    }

    try {
      // Get org settings for LLM config
      const orgSettings = await prisma.orgSettings.findUnique({
        where: { organizationId: project.organizationId },
      });

      const { removeAllScansForProject } = await import(
        "@/lib/remove-project-scans"
      );
      await removeAllScansForProject(project.id);

      // Create scan record
      const scan = await prisma.scan.create({
        data: {
          projectId: project.id,
          scanType: schedule.scanType,
          branch: schedule.branch || project.defaultBranch,
          sourceType: "GIT_CLONE",
          sourceRef: project.repoUrl,
          triggeredBy: "scheduler",
          status: "QUEUED",
        },
      });

      // Build job data
      const jobData: ScanJobData = {
        scanId: scan.id,
        projectId: project.id,
        sourceType: "GIT_CLONE",
        sourceRef: project.repoUrl,
        scanType: schedule.scanType as ScanJobData["scanType"],
        repoUrl: project.repoUrl,
        branch: schedule.branch || project.defaultBranch,
        orgSettings: buildOrgSettingsForJob(orgSettings, project.organizationId),
        dastTargetUrl: project.dastTargetUrl || undefined,
        buildGate: project.buildGate
          ? {
              maxCritical: project.buildGate.maxCritical,
              maxHigh: project.buildGate.maxHigh,
              maxMedium: project.buildGate.maxMedium,
              maxLow: project.buildGate.maxLow,
              failOnNew: project.buildGate.failOnNew,
            }
          : undefined,
      };

      // Enqueue
      const job = await scanQueue.add("scan", jobData, {
        jobId: scan.id,
      });

      await prisma.scan.update({
        where: { id: scan.id },
        data: { jobId: job.id },
      });

      // Update schedule
      await prisma.scanSchedule.update({
        where: { id: schedule.id },
        data: {
          lastRunAt: now,
          nextRunAt: computeNextRun(schedule.frequency),
        },
      });

      logger.info(
        {
          projectId: project.id,
          projectName: project.name,
          scanId: scan.id,
          frequency: schedule.frequency,
        },
        "Scheduled scan enqueued",
      );
    } catch (err) {
      logger.error(
        { err, projectId: project.id },
        "Failed to enqueue scheduled scan",
      );
    }
  }
}
