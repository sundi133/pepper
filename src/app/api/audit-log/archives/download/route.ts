import { NextRequest, NextResponse } from "next/server";
import { Readable } from "node:stream";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import { isOrgArchiveKey } from "@/lib/audit-retention";
import { minioClient, BUCKET } from "@/lib/minio";

/** Stream one archive (gzipped NDJSON) through the app, so object storage needn't be reachable from browsers. */
export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const roleAuth = await requireRole(orgId, "SECURITY");
  if ("error" in roleAuth) return roleAuth.error;

  const key = new URL(req.url).searchParams.get("key") ?? "";
  if (!isOrgArchiveKey(orgId, key)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  let body: Readable;
  try {
    body = await minioClient.getObject(BUCKET, key);
  } catch {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "audit.exported",
    resource: "audit",
    details: { archive: key },
    ipAddress: ipFromHeaders(req.headers),
  });
  const filename = key.split("/").pop()!;
  return new Response(Readable.toWeb(body) as ReadableStream, {
    headers: {
      "Content-Type": "application/gzip",
      "Content-Disposition": `attachment; filename="audit-${filename}"`,
      "Cache-Control": "no-store",
    },
  });
}
