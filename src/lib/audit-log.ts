import { prisma } from "@/lib/prisma";
import { Prisma } from "@/generated/prisma/client";
import type { AuditAction, AuditResource } from "@/lib/audit-actions";

export type { AuditAction, AuditResource };

export interface AuditWrite {
  organizationId: string | null;
  userId: string | null;
  action: AuditAction;
  resource: AuditResource;
  resourceId?: string | null;
  details?: Record<string, unknown> | null;
  ipAddress?: string | null;
}

export async function writeAuditLog(entry: AuditWrite): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        organizationId: entry.organizationId,
        userId: entry.userId,
        action: entry.action,
        resource: entry.resource,
        resourceId: entry.resourceId ?? null,
        details:
          entry.details === undefined || entry.details === null
            ? Prisma.JsonNull
            : (entry.details as Prisma.InputJsonValue),
        ipAddress: entry.ipAddress ?? null,
      },
    });
  } catch (e) {
    // Audit logging must never break the calling action
    console.warn("[audit-log] write failed:", e);
  }
}

/**
 * Record an event about a user (login, logout…) in every organization they
 * belong to, or instance-wide when they have none / aren't known.
 */
export async function writeUserAuditEvent(entry: {
  userId: string | null;
  action: AuditAction;
  details?: Record<string, unknown> | null;
  ipAddress?: string | null;
}): Promise<void> {
  let orgIds: Array<string | null> = [];
  try {
    if (entry.userId) {
      const memberships = await prisma.orgMember.findMany({
        where: { userId: entry.userId },
        select: { organizationId: true },
      });
      orgIds = memberships.map((m) => m.organizationId);
    }
  } catch (e) {
    console.warn("[audit-log] membership lookup failed:", e);
  }
  if (orgIds.length === 0) orgIds = [null];
  await Promise.all(
    orgIds.map((organizationId) =>
      writeAuditLog({
        organizationId,
        userId: entry.userId,
        action: entry.action,
        resource: "user",
        resourceId: entry.userId,
        details: entry.details,
        ipAddress: entry.ipAddress,
      }),
    ),
  );
}

/** Client IP from a plain header record (NextAuth `authorize` requests). */
export function ipFromHeaderRecord(headers: Record<string, unknown> | undefined): string | null {
  const get = (k: string) => {
    const v = headers?.[k];
    return typeof v === "string" ? v : Array.isArray(v) && typeof v[0] === "string" ? v[0] : undefined;
  };
  return get("x-forwarded-for")?.split(",")[0]?.trim() || get("x-real-ip") || null;
}

export interface AuditQueryParams {
  organizationId: string;
  cursor?: string;
  limit?: number;
  action?: string;
  resource?: string;
  userId?: string;
  from?: Date;
  to?: Date;
}

export function auditWhere(params: Omit<AuditQueryParams, "cursor" | "limit">) {
  return {
    organizationId: params.organizationId,
    ...(params.action ? { action: params.action } : {}),
    ...(params.resource ? { resource: params.resource } : {}),
    ...(params.userId ? { userId: params.userId } : {}),
    ...(params.from || params.to
      ? {
          createdAt: {
            ...(params.from ? { gte: params.from } : {}),
            ...(params.to ? { lte: params.to } : {}),
          },
        }
      : {}),
  };
}

/** Newest first; id breaks timestamp ties so cursor paging never skips rows. */
export const AUDIT_ORDER = [{ createdAt: "desc" as const }, { id: "desc" as const }];

export async function queryAuditLog(params: AuditQueryParams) {
  const take = Math.min(Math.max(params.limit ?? 50, 1), 200);
  const rows = await prisma.auditLog.findMany({
    where: auditWhere(params),
    orderBy: AUDIT_ORDER,
    take: take + 1,
    ...(params.cursor ? { cursor: { id: params.cursor }, skip: 1 } : {}),
  });

  const nextCursor = rows.length > take ? rows[take].id : null;
  return { rows: rows.slice(0, take), nextCursor };
}

export function ipFromHeaders(headers: Headers): string | null {
  const xff = headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0]!.trim();
  return headers.get("x-real-ip");
}
