/**
 * Retention for uploaded source code and scan history. Runs in the worker; a
 * Redis lock keeps it to one run per window across worker replicas.
 *
 * - UPLOAD_RETENTION_DAYS: uploaded source archives (scans/<id>/source.zip)
 *   are deleted this many days after upload. Scan results are kept; a rescan
 *   of that project then asks for the archive to be uploaded again.
 * - SCAN_HISTORY_RETENTION_DAYS: scan history (trend snapshots and their
 *   finding copies) and finished AI remediation runs (analysis, diffs, event
 *   logs) older than this are deleted. Each project's latest snapshot per scan
 *   type is always kept, so "new since last scan" keeps working. The current
 *   scan and its findings are never touched.
 *
 * Both are off by default: nothing is deleted unless the variable is set.
 */
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { redis } from "@/lib/redis";
import { minioClient, BUCKET, deleteObject } from "@/lib/minio";
import { writeAuditLog } from "@/lib/audit-log";

/** Shortest windows accepted, so a typo can't wipe data that's still in use. */
export const MIN_UPLOAD_RETENTION_DAYS = 1;
export const MIN_HISTORY_RETENTION_DAYS = 30;

const LOCK_KEY = "pepper:data-retention:lock";
const RUN_EVERY_SECONDS = 6 * 60 * 60;
const TICK_MS = 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;
const DELETE_BATCH = 500;

/** Scans that may still read their uploaded archive. */
const ACTIVE_SCAN_STATUSES = ["QUEUED", "RUNNING", "PAUSED"] as const;
const FINISHED_REMEDIATION_STATUSES = ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"] as const;

/** Object keys of uploaded source archives (see POST /api/scans). */
const UPLOAD_SOURCE_KEY = /^scans\/[^/]+\/source\.(?:zip|tar\.gz|tgz|tar)$/i;

export function isUploadSourceKey(key: string): boolean {
  return UPLOAD_SOURCE_KEY.test(key);
}

function daysFromEnv(raw: string | undefined, min: number): number | null {
  const value = raw?.trim();
  if (!value) return null;
  const days = Number(value);
  if (!Number.isInteger(days) || days <= 0) return null;
  return Math.max(days, min);
}

/** UPLOAD_RETENTION_DAYS; null = keep uploads forever. */
export function uploadRetentionDays(env: Record<string, string | undefined> = process.env): number | null {
  return daysFromEnv(env.UPLOAD_RETENTION_DAYS, MIN_UPLOAD_RETENTION_DAYS);
}

/** SCAN_HISTORY_RETENTION_DAYS; null = keep history forever. */
export function scanHistoryRetentionDays(env: Record<string, string | undefined> = process.env): number | null {
  return daysFromEnv(env.SCAN_HISTORY_RETENTION_DAYS, MIN_HISTORY_RETENTION_DAYS);
}

/** Message for a rescan / resume whose archive was removed by retention. */
export function uploadExpiredMessage(): string {
  const days = uploadRetentionDays();
  return (
    `The uploaded source for this project was deleted by the data retention policy` +
    (days ? ` (uploads are kept ${days} day${days === 1 ? "" : "s"})` : "") +
    ". Upload the archive again to scan it."
  );
}

export interface UploadPurgeResult {
  retentionDays: number;
  cutoff: Date;
  deleted: number;
  /** Expired archives kept because a queued, running or paused scan uses them. */
  inUse: number;
  byOrganization: Map<string | null, number>;
  error?: string;
}

async function listExpiredUploads(cutoff: Date): Promise<string[]> {
  const keys: string[] = [];
  const stream = minioClient.listObjectsV2(BUCKET, "scans/", true);
  for await (const obj of stream as AsyncIterable<{ name?: string; lastModified?: Date }>) {
    if (obj.name && isUploadSourceKey(obj.name) && obj.lastModified && obj.lastModified < cutoff) {
      keys.push(obj.name);
    }
  }
  return keys;
}

/** Delete uploaded source archives older than `days`. */
export async function purgeExpiredUploads(days: number, now = new Date()): Promise<UploadPurgeResult> {
  const cutoff = new Date(now.getTime() - days * DAY_MS);
  const result: UploadPurgeResult = { retentionDays: days, cutoff, deleted: 0, inUse: 0, byOrganization: new Map() };

  let expired: string[];
  try {
    expired = await listExpiredUploads(cutoff);
  } catch (e) {
    result.error = `Could not list uploads: ${e instanceof Error ? e.message : String(e)}`;
    return result;
  }

  for (let i = 0; i < expired.length; i += DELETE_BATCH) {
    const keys = expired.slice(i, i + DELETE_BATCH);
    const scans = await prisma.scan.findMany({
      where: { sourceType: "UPLOAD", sourceRef: { in: keys } },
      select: { sourceRef: true, status: true, project: { select: { organizationId: true } } },
    });
    const orgByKey = new Map<string, string>();
    const inUse = new Set<string>();
    for (const s of scans) {
      if (!s.sourceRef) continue;
      orgByKey.set(s.sourceRef, s.project.organizationId);
      if ((ACTIVE_SCAN_STATUSES as readonly string[]).includes(s.status)) inUse.add(s.sourceRef);
    }
    for (const key of keys) {
      if (inUse.has(key)) {
        result.inUse++;
        continue;
      }
      try {
        await deleteObject(key);
      } catch (e) {
        result.error = `Could not delete ${key}: ${e instanceof Error ? e.message : String(e)}`;
        continue;
      }
      result.deleted++;
      const org = orgByKey.get(key) ?? null;
      result.byOrganization.set(org, (result.byOrganization.get(org) ?? 0) + 1);
    }
  }
  return result;
}

export interface HistoryPurgeResult {
  retentionDays: number;
  cutoff: Date;
  snapshots: number;
  remediationRuns: number;
  byOrganization: Map<string, { snapshots: number; remediationRuns: number }>;
}

/** Delete scan history snapshots and finished remediation runs older than `days`. */
export async function purgeScanHistory(days: number, now = new Date()): Promise<HistoryPurgeResult> {
  const cutoff = new Date(now.getTime() - days * DAY_MS);
  const result: HistoryPurgeResult = { retentionDays: days, cutoff, snapshots: 0, remediationRuns: 0, byOrganization: new Map() };
  const tally = (org: string, field: "snapshots" | "remediationRuns", n: number) => {
    const t = result.byOrganization.get(org) ?? { snapshots: 0, remediationRuns: 0 };
    t[field] += n;
    result.byOrganization.set(org, t);
  };

  const old = await prisma.scanSnapshot.findMany({
    where: { completedAt: { lt: cutoff } },
    select: { id: true, projectId: true, organizationId: true },
  });
  if (old.length > 0) {
    // Newest snapshot of each project and scan type stays: it's the baseline
    // for the next scan's "new / resolved since last scan".
    const latest = await prisma.scanSnapshot.findMany({
      where: { projectId: { in: [...new Set(old.map((s) => s.projectId))] } },
      orderBy: [{ projectId: "asc" }, { scanType: "asc" }, { completedAt: "desc" }],
      distinct: ["projectId", "scanType"],
      select: { id: true },
    });
    const keep = new Set(latest.map((s) => s.id));
    const expired = old.filter((s) => !keep.has(s.id));
    for (let i = 0; i < expired.length; i += DELETE_BATCH) {
      const batch = expired.slice(i, i + DELETE_BATCH);
      const { count } = await prisma.scanSnapshot.deleteMany({ where: { id: { in: batch.map((s) => s.id) } } });
      result.snapshots += count;
      for (const s of batch) tally(s.organizationId, "snapshots", 1);
    }
  }

  const runs = await prisma.remediationRun.findMany({
    where: { createdAt: { lt: cutoff }, status: { in: [...FINISHED_REMEDIATION_STATUSES] } },
    select: { id: true, organizationId: true },
  });
  for (let i = 0; i < runs.length; i += DELETE_BATCH) {
    const batch = runs.slice(i, i + DELETE_BATCH);
    const { count } = await prisma.remediationRun.deleteMany({
      where: { id: { in: batch.map((r) => r.id) }, status: { in: [...FINISHED_REMEDIATION_STATUSES] } },
    });
    result.remediationRuns += count;
    for (const r of batch) tally(r.organizationId, "remediationRuns", 1);
  }
  return result;
}

/** Apply both policies once and record what was deleted in each organization's audit log. */
export async function runDataRetention(now = new Date()): Promise<{
  uploads: UploadPurgeResult | null;
  history: HistoryPurgeResult | null;
}> {
  const uploadDays = uploadRetentionDays();
  const historyDays = scanHistoryRetentionDays();

  let uploads: UploadPurgeResult | null = null;
  if (uploadDays != null) {
    uploads = await purgeExpiredUploads(uploadDays, now);
    for (const [organizationId, deleted] of uploads.byOrganization) {
      await writeAuditLog({
        organizationId,
        userId: null,
        action: "scan.uploads_purged",
        resource: "scan",
        details: { retentionDays: uploadDays, olderThan: uploads.cutoff.toISOString(), deleted },
      });
    }
    if (uploads.error) {
      await writeAuditLog({
        organizationId: null,
        userId: null,
        action: "scan.purge_failed",
        resource: "scan",
        details: { kind: "uploads", retentionDays: uploadDays, error: uploads.error },
      });
    }
  }

  let history: HistoryPurgeResult | null = null;
  if (historyDays != null) {
    history = await purgeScanHistory(historyDays, now);
    for (const [organizationId, counts] of history.byOrganization) {
      await writeAuditLog({
        organizationId,
        userId: null,
        action: "scan.history_purged",
        resource: "scan",
        details: { retentionDays: historyDays, olderThan: history.cutoff.toISOString(), ...counts },
      });
    }
  }
  return { uploads, history };
}

async function acquireRunLock(): Promise<boolean> {
  try {
    return (await redis.set(LOCK_KEY, String(process.pid), "EX", RUN_EVERY_SECONDS, "NX")) === "OK";
  } catch (err) {
    logger.warn({ err }, "Data retention skipped: Redis unavailable for the run lock");
    return false;
  }
}

async function tick() {
  if (uploadRetentionDays() == null && scanHistoryRetentionDays() == null) return;
  if (!(await acquireRunLock())) return;
  const { uploads, history } = await runDataRetention();
  if (uploads && (uploads.deleted > 0 || uploads.error)) {
    logger.info({ deleted: uploads.deleted, inUse: uploads.inUse, error: uploads.error }, "Upload retention purge finished");
  }
  if (history && (history.snapshots > 0 || history.remediationRuns > 0)) {
    logger.info({ snapshots: history.snapshots, remediationRuns: history.remediationRuns }, "Scan history retention purge finished");
  }
}

/** Start the hourly check in the worker; returns the interval to clear on shutdown. */
export function startDataRetention(): NodeJS.Timeout {
  const run = () => tick().catch((err) => logger.error({ err }, "Data retention run failed"));
  setTimeout(run, 3 * 60 * 1000).unref();
  return setInterval(run, TICK_MS);
}
