import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId, requireRole } from "@/lib/auth-guard";
import { writeAuditLog, ipFromHeaders } from "@/lib/audit-log";
import { TICKET_FINDING_SELECT } from "@/lib/integrations/finding-tickets";
import {
  BULK_TICKET_LIMIT,
  TICKET_KIND_LABELS,
  loadTicketIntegrations,
  raiseTicketsForFindings,
} from "@/lib/integrations/bulk-tickets";

function scanWebUrl(scanId: string): string | undefined {
  const base = process.env.NEXTAUTH_URL || process.env.APP_URL || process.env.NEXT_PUBLIC_APP_URL;
  return base ? `${base.replace(/\/+$/, "")}/scans/${scanId}` : undefined;
}

async function scanInOrg(scanId: string, orgId: string) {
  return prisma.scan.findFirst({
    where: { id: scanId, project: { organizationId: orgId } },
    select: {
      id: true,
      branch: true,
      project: { select: { id: true, name: true, organizationId: true, azureProjectName: true } },
    },
  });
}

/** The ticket systems findings of this scan can be filed to. */
export async function GET(_req: NextRequest, { params }: { params: Promise<{ scanId: string }> }) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  const { scanId } = await params;
  if (!(await scanInOrg(scanId, orgId))) return NextResponse.json({ error: "Scan not found" }, { status: 404 });

  const integrations = await loadTicketIntegrations(orgId);
  return NextResponse.json({
    limit: BULK_TICKET_LIMIT,
    targets: integrations.map((i) => ({ id: i.id, name: i.name, kind: i.kind, kindLabel: TICKET_KIND_LABELS[i.kind] })),
  });
}

/**
 * File tickets for the selected findings. Body: `{ findingIds, integrationIds }`.
 * Each issue is filed once per ticket project; already-filed ones are
 * returned as existing. Results are reported per integration.
 */
export async function POST(req: NextRequest, { params }: { params: Promise<{ scanId: string }> }) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return NextResponse.json({ error: "No organization" }, { status: 403 });
  // Creates tickets in external systems, like the single-finding action.
  const roleAuth = await requireRole(orgId, "DEVELOPER");
  if ("error" in roleAuth) return roleAuth.error;

  const { scanId } = await params;
  const scan = await scanInOrg(scanId, orgId);
  if (!scan?.project) return NextResponse.json({ error: "Scan not found" }, { status: 404 });

  let body: { findingIds?: unknown; integrationIds?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }
  const strings = (v: unknown) =>
    Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === "string" && x.length > 0))] : [];
  const findingIds = strings(body.findingIds);
  const integrationIds = strings(body.integrationIds);
  if (findingIds.length === 0) return NextResponse.json({ error: "Select at least one finding" }, { status: 400 });
  if (findingIds.length > BULK_TICKET_LIMIT) {
    return NextResponse.json({ error: `Select at most ${BULK_TICKET_LIMIT} findings at a time` }, { status: 400 });
  }
  if (integrationIds.length === 0) return NextResponse.json({ error: "Choose at least one ticket system" }, { status: 400 });

  const integrations = await loadTicketIntegrations(orgId, integrationIds);
  if (integrations.length === 0) {
    return NextResponse.json({ error: "None of the chosen ticket systems is configured and enabled" }, { status: 400 });
  }
  const findings = await prisma.finding.findMany({
    where: { id: { in: findingIds }, scanId: scan.id },
    select: TICKET_FINDING_SELECT,
    orderBy: [{ severity: "asc" }, { createdAt: "asc" }],
  });
  if (findings.length === 0) return NextResponse.json({ error: "No matching findings in this scan" }, { status: 404 });

  const results = await raiseTicketsForFindings({
    orgId,
    repo: { ...scan.project, organizationId: orgId },
    findings: findings.map((f) => ({ ...f, branch: scan.branch })),
    integrations,
    scanUrl: scanWebUrl(scan.id),
  });

  await writeAuditLog({
    organizationId: orgId,
    userId: auth.session.user.id,
    action: "finding.ticket_raised",
    resource: "scan",
    resourceId: scan.id,
    details: {
      bulk: true,
      findings: findings.length,
      integrations: results.map((r) => ({ name: r.name, created: r.created, existing: r.existing, failed: r.failed.length })),
    },
    ipAddress: ipFromHeaders(req.headers),
  });

  const anyOk = results.some((r) => r.created + r.existing > 0);
  return NextResponse.json({ ok: anyOk, findings: findings.length, results }, { status: anyOk ? 200 : 502 });
}
