import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { prisma } from "@/lib/prisma";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import { auditRows, exportStream, parseAuditFilters } from "@/lib/audit-export";

/**
 * Download the organization's audit log as CSV or JSON, with the same
 * filters as the list (`from`, `to`, `action`, `resource`, `userId`).
 * Streamed, so large ranges don't have to fit in memory.
 */
export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const url = new URL(req.url);
  const format = (url.searchParams.get("format") || "csv").toLowerCase();
  if (format !== "csv" && format !== "json") {
    return NextResponse.json({ error: 'format must be "csv" or "json"' }, { status: 400 });
  }
  const parsed = parseAuditFilters(url.searchParams);
  if ("error" in parsed) {
    return NextResponse.json({ error: parsed.error }, { status: 400 });
  }
  const { filters } = parsed;

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "audit.exported",
    resource: "audit",
    details: {
      format,
      ...filters,
      from: filters.from?.toISOString(),
      to: filters.to?.toISOString(),
    },
    ipAddress: ipFromHeaders(req.headers),
  });

  const org = await prisma.organization.findUnique({ where: { id: orgId }, select: { slug: true } });
  const day = (d?: Date) => d?.toISOString().slice(0, 10);
  const range = [day(filters.from), day(filters.to) ?? day(new Date())].filter(Boolean).join("_to_");
  const filename = `pepper-audit-log-${org?.slug ?? "org"}-${range}.${format}`.replace(/[^\w.-]+/g, "-");

  return new Response(exportStream(format, auditRows(orgId, filters)), {
    headers: {
      "Content-Type": format === "csv" ? "text/csv; charset=utf-8" : "application/json; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
    },
  });
}
