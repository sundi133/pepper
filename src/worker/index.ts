import "dotenv/config";
import { Worker } from "bullmq";
import { SCAN_QUEUE_NAME, ScanJobData } from "@/lib/queue";
import { redisConnection } from "@/lib/redis";
import { ensureBucket } from "@/lib/minio";
import { processScanJob } from "./scan-processor";
import { logger } from "@/lib/logger";
import { prisma } from "@/lib/prisma";

async function main() {
  logger.info("Starting Pepper scan worker...");

  // Ensure MinIO bucket exists
  await ensureBucket();
  logger.info("MinIO bucket ready");

  const concurrency = parseInt(process.env.WORKER_CONCURRENCY || "2");

  const worker = new Worker<ScanJobData>(SCAN_QUEUE_NAME, processScanJob, {
    connection: redisConnection,
    concurrency,
    lockDuration: 300_000, // 5 minutes — enough for slow LLM batches
    lockRenewTime: 150_000, // renew halfway through lock period
    stalledInterval: 300_000, // match lock duration to avoid false stalls
    limiter: {
      max: 10,
      duration: 60_000,
    },
  });

  worker.on("completed", (job) => {
    logger.info(
      { jobId: job.id, scanId: job.data.scanId },
      "Scan job completed",
    );
  });

  worker.on("failed", async (job, error) => {
    logger.error(
      { jobId: job?.id, scanId: job?.data.scanId, error: error.message },
      "Scan job failed",
    );

    if (job?.data.scanId) {
      try {
        await prisma.scan.update({
          where: { id: job.data.scanId },
          data: {
            status: "FAILED",
            completedAt: new Date(),
            errorMessage: error.message,
          },
        });
      } catch {
        // ignore DB update errors
      }
    }
  });

  worker.on("error", (error) => {
    logger.error({ error: error.message }, "Worker error");
  });

  // Graceful shutdown
  const shutdown = async () => {
    logger.info("Shutting down worker...");
    await worker.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  logger.info({ concurrency }, "Worker started and waiting for jobs");
}

main().catch((error) => {
  logger.error({ error }, "Worker failed to start");
  process.exit(1);
});
