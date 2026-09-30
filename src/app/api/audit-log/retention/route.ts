import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import {
  MIN_RETENTION_DAYS,
  effectiveRetentionDays,
  instanceRetentionDays,
} from "@/lib/audit-retention";

const MAX_RETENTION_DAYS = 3650;

async function current(orgId: string) {
  const settings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
    select: { auditLogRetentionDays: true, auditLogArchive: true },
  });
  const lastPurge = await prisma.auditLog.findFirst({
    where: { organizationId: orgId, action: { in: ["audit.purged", "audit.purge_failed"] } },
    orderBy: { createdAt: "desc" },
    select: { action: true, createdAt: true, details: true },
  });
  const instanceDays = instanceRetentionDays();
  return {
    retentionDays: settings?.auditLogRetentionDays ?? null,
    archive: settings?.auditLogArchive ?? true,
    instanceDefaultDays: instanceDays,
    effectiveDays: effectiveRetentionDays(settings?.auditLogRetentionDays, instanceDays),
    minDays: MIN_RETENTION_DAYS,
    lastPurge,
  };
}

export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;
  return NextResponse.json(await current(orgId));
}

/**
 * Body: `{ retentionDays: number | null, archive?: boolean }` — null uses the
 * instance default, 0 keeps entries forever, otherwise at least 30 days.
 */
export async function PUT(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "ADMIN");
  if ("error" in roleAuth) return roleAuth.error;

  let body: { retentionDays?: unknown; archive?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const days = body.retentionDays;
  const validDays =
    days === null ||
    days === 0 ||
    (typeof days === "number" && Number.isInteger(days) && days >= MIN_RETENTION_DAYS && days <= MAX_RETENTION_DAYS);
  if (!validDays) {
    return NextResponse.json(
      { error: `retentionDays must be null (instance default), 0 (keep forever) or ${MIN_RETENTION_DAYS}–${MAX_RETENTION_DAYS}` },
      { status: 400 },
    );
  }
  if (body.archive !== undefined && typeof body.archive !== "boolean") {
    return NextResponse.json({ error: "archive must be a boolean" }, { status: 400 });
  }
  const before = await current(orgId);
  const data = {
    auditLogRetentionDays: days as number | null,
    ...(typeof body.archive === "boolean" ? { auditLogArchive: body.archive } : {}),
  };
  await prisma.orgSettings.upsert({
    where: { organizationId: orgId },
    create: { organizationId: orgId, ...data },
    update: data,
  });

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "settings.audit.updated",
    resource: "settings",
    resourceId: orgId,
    details: {
      retentionDays: { from: before.retentionDays, to: data.auditLogRetentionDays },
      archive: { from: before.archive, to: data.auditLogArchive ?? before.archive },
    },
    ipAddress: ipFromHeaders(req.headers),
  });

  return NextResponse.json(await current(orgId));
}
