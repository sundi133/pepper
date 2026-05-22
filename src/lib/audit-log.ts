import { prisma } from "@/lib/prisma";
import { Prisma } from "@/generated/prisma/client";

export type AuditAction =
  | "user.login"
  | "user.logout"
  | "user.created"
  | "user.invited"
  | "user.role_changed"
  | "user.removed"
  | "project.created"
  | "project.updated"
  | "project.deleted"
  | "scan.queued"
  | "scan.cancelled"
  | "scan.paused"
  | "scan.resumed"
  | "scan.rescanned"
  | "scan.stopped"
  | "finding.status_changed"
  | "finding.suggest_fix"
  | "finding.open_pr"
  | "buildgate.updated"
  | "policy.created"
  | "policy.updated"
  | "policy.deleted"
  | "integration.created"
  | "integration.updated"
  | "integration.deleted"
  | "integration.tested"
  | "apikey.created"
  | "apikey.revoked"
  | "settings.updated"
  | "settings.llm.updated"
  | "settings.dast.updated"
  | "settings.signing.updated"
  | "settings.webhooks.updated";

export type AuditResource =
  | "user"
  | "project"
  | "scan"
  | "finding"
  | "buildgate"
  | "policy"
  | "integration"
  | "apikey"
  | "settings"
  | "organization";

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

export async function queryAuditLog(params: AuditQueryParams) {
  const take = Math.min(Math.max(params.limit ?? 50, 1), 200);
  const where = {
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

  const rows = await prisma.auditLog.findMany({
    where,
    orderBy: { createdAt: "desc" },
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
