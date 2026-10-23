import { NextRequest, NextResponse } from "next/server";
import { requireAuth, getActiveOrgId, requireRole } from "@/lib/auth-guard";
import { parseRescanBody } from "@/lib/scan-types";
import { ipFromHeaders } from "@/lib/audit-log";
import { rescanScan } from "@/lib/scan-rescan";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  // Body is optional: an empty POST keeps the original behaviour.
  const body = parseRescanBody(await req.text().catch(() => ""));
  if (!body.ok) {
    return NextResponse.json({ error: body.error }, { status: 400 });
  }
  const requestedScanType = body.scanType;

  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const roleAuth = await requireRole(orgId, "DEVELOPER");
  if ("error" in roleAuth) return roleAuth.error;

  const { scanId } = await params;

  const result = await rescanScan({
    orgId,
    userId: auth.session.user.id,
    scanId,
    scanType: requestedScanType,
    ipAddress: ipFromHeaders(req.headers),
  });
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json(
    { scanId: result.scanId, status: "QUEUED" },
    { status: 201 },
  );
}
