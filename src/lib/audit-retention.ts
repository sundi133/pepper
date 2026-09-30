/**
 * Audit log retention: delete entries older than each organization's
 * retention window, copying them to object storage first (gzipped NDJSON)
 * unless the organization turned archiving off. Runs in the worker; a Redis
 * lock keeps it to one run per window across worker replicas.
 *
 * Default is to keep everything: nothing is deleted unless an organization
 * sets a retention period or the instance sets AUDIT_LOG_RETENTION_DAYS.
 */
import { gzipSync } from "node:zlib";
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { redis } from "@/lib/redis";
import { minioClient, BUCKET, uploadObject } from "@/lib/minio";
import { writeAuditLog } from "@/lib/audit-log";

/** Shortest retention accepted, so a typo can't wipe the log. */
export const MIN_RETENTION_DAYS = 30;
/** Rows per archive object / delete batch. */
const BATCH = 5000;
const ARCHIVE_PREFIX = "audit-archive";
const LOCK_KEY = "pepper:audit-retention:lock";
/** At most one purge per this window, cluster-wide. */
const RUN_EVERY_SECONDS = 6 * 60 * 60;
const TICK_MS = 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

/** Instance default from AUDIT_LOG_RETENTION_DAYS; null = keep forever. */
export function instanceRetentionDays(env: Record<string, string | undefined> = process.env): number | null {
  const raw = env.AUDIT_LOG_RETENTION_DAYS?.trim();
  if (!raw) return null;
  const days = Number(raw);
  if (!Number.isInteger(days) || days <= 0) return null;
  return Math.max(days, MIN_RETENTION_DAYS);
}

/**
 * The window that applies to an organization: its own setting (0 = keep
 * forever), else the instance default. Null = keep forever.
 */
export function effectiveRetentionDays(orgSetting: number | null | undefined, instanceDays: number | null): number | null {
  if (orgSetting === 0) return null;
  if (orgSetting != null && orgSetting > 0) return Math.max(orgSetting, MIN_RETENTION_DAYS);
  return instanceDays;
}

/** Object key prefix holding an organization's archives. */
export function archivePrefix(organizationId: string | null): string {
  return `${ARCHIVE_PREFIX}/${organizationId ?? "_instance"}/`;
}

function compactTimestamp(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}

export function archiveKey(organizationId: string | null, first: Date, last: Date, count: number): string {
  return `${archivePrefix(organizationId)}${first.getUTCFullYear()}/${compactTimestamp(first)}_${compactTimestamp(last)}_${count}.ndjson.gz`;
}

type AuditRow = {
  id: string;
  organizationId: string | null;
  userId: string | null;
  action: string;
  resource: string;
  resourceId: string | null;
  details: unknown;
  ipAddress: string | null;
  createdAt: Date;
};

export function toArchiveNdjson(rows: AuditRow[]): Buffer {
  const text = rows.map((r) => JSON.stringify({ ...r, createdAt: r.createdAt.toISOString() })).join("\n") + "\n";
  return gzipSync(Buffer.from(text, "utf8"));
}

export interface PurgeResult {
  organizationId: string | null;
  retentionDays: number;
  cutoff: Date;
  deleted: number;
  archiveObjects: number;
  error?: string;
}

/**
 * Delete one organization's entries older than `days`, oldest first, in
 * batches. With `archive`, each batch is uploaded before it is deleted; an
 * upload failure stops the purge so nothing is lost.
 */
export async function purgeOrganization(
  organizationId: string | null,
  days: number,
  archive: boolean,
  now = new Date(),
): Promise<PurgeResult> {
  const cutoff = new Date(now.getTime() - days * DAY_MS);
  const result: PurgeResult = { organizationId, retentionDays: days, cutoff, deleted: 0, archiveObjects: 0 };
  for (;;) {
    const rows = (await prisma.auditLog.findMany({
      where: { organizationId, createdAt: { lt: cutoff } },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      take: BATCH,
    })) as AuditRow[];
    if (rows.length === 0) break;
    if (archive) {
      try {
        const key = archiveKey(organizationId, rows[0].createdAt, rows[rows.length - 1].createdAt, rows.length);
        await uploadObject(key, toArchiveNdjson(rows), "application/gzip");
        result.archiveObjects++;
      } catch (e) {
        result.error = `Archive upload failed, nothing more was deleted: ${e instanceof Error ? e.message : String(e)}`;
        break;
      }
    }
    const { count } = await prisma.auditLog.deleteMany({ where: { id: { in: rows.map((r) => r.id) } } });
    result.deleted += count;
    if (rows.length < BATCH) break;
  }
  return result;
}

/** Purge every organization (and instance-level entries) past its window. */
export async function purgeExpiredAuditLogs(now = new Date()): Promise<PurgeResult[]> {
  const instanceDays = instanceRetentionDays();
  const orgs = await prisma.organization.findMany({
    select: { id: true, settings: { select: { auditLogRetentionDays: true, auditLogArchive: true } } },
  });
  const results: PurgeResult[] = [];
  const targets: Array<{ id: string | null; days: number; archive: boolean }> = [];
  for (const org of orgs) {
    const days = effectiveRetentionDays(org.settings?.auditLogRetentionDays, instanceDays);
    if (days != null) targets.push({ id: org.id, days, archive: org.settings?.auditLogArchive ?? true });
  }
  // Entries with no organization (e.g. failed logins for unknown emails).
  if (instanceDays != null) targets.push({ id: null, days: instanceDays, archive: true });

  for (const t of targets) {
    const res = await purgeOrganization(t.id, t.days, t.archive, now);
    results.push(res);
    if (res.deleted > 0 || res.error) {
      await writeAuditLog({
        organizationId: t.id,
        userId: null,
        action: res.error ? "audit.purge_failed" : "audit.purged",
        resource: "audit",
        details: {
          retentionDays: t.days,
          olderThan: res.cutoff.toISOString(),
          deleted: res.deleted,
          archived: t.archive,
          archiveObjects: res.archiveObjects,
          ...(res.error ? { error: res.error } : {}),
        },
      });
    }
  }
  return results;
}

/** Take the cluster-wide lock for this window; false if another run holds it. */
async function acquireRunLock(): Promise<boolean> {
  try {
    return (await redis.set(LOCK_KEY, String(process.pid), "EX", RUN_EVERY_SECONDS, "NX")) === "OK";
  } catch (err) {
    logger.warn({ err }, "Audit retention skipped: Redis unavailable for the run lock");
    return false;
  }
}

async function tick() {
  if (!(await acquireRunLock())) return;
  const results = await purgeExpiredAuditLogs();
  const deleted = results.reduce((n, r) => n + r.deleted, 0);
  const failed = results.filter((r) => r.error);
  if (deleted > 0 || failed.length > 0) {
    logger.info({ deleted, organizations: results.length, failed: failed.length }, "Audit log retention purge finished");
  }
  for (const f of failed) logger.warn({ organizationId: f.organizationId, error: f.error }, "Audit log purge stopped");
}

/** Start the hourly check in the worker; returns the interval to clear on shutdown. */
export function startAuditRetention(): NodeJS.Timeout {
  const run = () => tick().catch((err) => logger.error({ err }, "Audit log retention run failed"));
  setTimeout(run, 2 * 60 * 1000).unref();
  return setInterval(run, TICK_MS);
}

export interface ArchiveObject {
  key: string;
  name: string;
  size: number;
  lastModified: string | null;
}

/** An organization's archive objects, newest first. */
export async function listAuditArchives(organizationId: string): Promise<ArchiveObject[]> {
  const prefix = archivePrefix(organizationId);
  const out: ArchiveObject[] = [];
  const stream = minioClient.listObjectsV2(BUCKET, prefix, true);
  for await (const obj of stream as AsyncIterable<{ name?: string; size?: number; lastModified?: Date }>) {
    if (!obj.name) continue;
    out.push({
      key: obj.name,
      name: obj.name.slice(prefix.length),
      size: obj.size ?? 0,
      lastModified: obj.lastModified ? obj.lastModified.toISOString() : null,
    });
  }
  return out.sort((a, b) => b.key.localeCompare(a.key));
}

/** True when `key` is one of this organization's archives (blocks path games). */
export function isOrgArchiveKey(organizationId: string, key: string): boolean {
  const prefix = archivePrefix(organizationId);
  return key.startsWith(prefix) && !key.includes("..") && key.endsWith(".ndjson.gz");
}
