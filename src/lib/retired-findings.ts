import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { recountScanSeverities } from "@/lib/scan-severity-counts";

/**
 * Detectors that were removed because what they matched was not a secret:
 * AWS_SECRET_KEY flagged any 40 base64 characters (npm integrity hashes, long
 * identifiers) and HEROKU_API_KEY any UUID (Postman ids). Scans made before
 * the removal still hold those findings, by the thousand, as open Criticals.
 * Only the pattern scanner's findings: the AI pass may report a real AWS
 * secret under the same rule id.
 */
export const RETIRED_RULES = [
  { scanner: "SECRETS_PATTERN", ruleId: "SECRET-AWS_SECRET_KEY" },
  { scanner: "SECRETS_PATTERN", ruleId: "SECRET-HEROKU_API_KEY" },
] as const;

export const RETIRED_NOTE = "Closed automatically: reported by a detector that was retired for false positives.";

/**
 * Mark still-open findings of retired detectors as false positives and refresh
 * the totals of the scans they belong to. Triage someone already did is left
 * alone. Safe to run repeatedly; returns how many findings were closed.
 */
export async function closeRetiredFindings(): Promise<number> {
  const where = { status: "OPEN" as const, OR: RETIRED_RULES.map((r) => ({ scanner: r.scanner as never, ruleId: r.ruleId })) };
  const scans = await prisma.finding.findMany({ where, select: { scanId: true }, distinct: ["scanId"] });
  if (scans.length === 0) return 0;
  const { count } = await prisma.finding.updateMany({
    where,
    data: { status: "FALSE_POSITIVE", statusNote: RETIRED_NOTE, statusUpdatedAt: new Date() },
  });
  await Promise.allSettled(scans.map((s) => recountScanSeverities(s.scanId)));
  logger.info({ findings: count, scans: scans.length }, "Closed findings of retired detectors");
  return count;
}

/** Run once, shortly after the worker starts. */
export function scheduleRetiredFindingsCleanup(): void {
  setTimeout(() => {
    closeRetiredFindings().catch((err) => logger.error({ err }, "Closing retired findings failed"));
  }, 60 * 1000).unref();
}
