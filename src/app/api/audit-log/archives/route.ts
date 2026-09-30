import { NextResponse } from "next/server";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { listAuditArchives } from "@/lib/audit-retention";
import { logger } from "@/lib/logger";

/** Archived (purged) audit entries in object storage, newest first. */
export async function GET() {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;
  try {
    return NextResponse.json({ archives: await listAuditArchives(orgId) });
  } catch (err) {
    logger.warn({ err }, "Listing audit archives failed");
    return NextResponse.json({ archives: [], error: "Object storage is unavailable" }, { status: 503 });
  }
}
