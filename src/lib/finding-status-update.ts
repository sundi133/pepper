import { prisma } from "@/lib/prisma";
import {
  enrichFindingWithReport,
  findingHasStoredReport,
} from "@/lib/finding-report";
import { generateSuppressionRule } from "@/lib/suppression-rules";
import { writeAuditLog } from "@/lib/audit-log";
import { recountScanSeverities } from "@/lib/scan-severity-counts";

/** Triage statuses a user may set on a finding. */
export const FINDING_STATUSES = [
  "OPEN",
  "IN_PROGRESS",
  "FALSE_POSITIVE",
  "ACCEPTED_RISK",
  "RESOLVED",
] as const;

export type FindingStatusValue = (typeof FINDING_STATUSES)[number];

/**
 * Change one finding's triage status, as the finding page does: record who and
 * when, write the audit entry, recount the scan's severity totals, and turn a
 * false positive into a suppression rule for future scans.
 *
 * The caller is responsible for authorization (role checks, including the
 * Security role for risk decisions). Returns null when the finding does not
 * exist in the organization.
 */
export async function applyFindingStatusChange(params: {
  orgId: string;
  userId: string;
  findingId: string;
  status: FindingStatusValue;
  statusNote?: string;
  ipAddress?: string | null;
  /** Extra audit detail naming the client that made the change (e.g. "mcp"). */
  via?: string;
}) {
  const { orgId, userId, findingId } = params;

  const existing = await prisma.finding.findFirst({
    where: {
      id: findingId,
      scan: { project: { organizationId: orgId } },
    },
    select: { id: true, status: true },
  });
  if (!existing) return null;

  const finding = await prisma.finding.update({
    where: { id: findingId },
    data: {
      status: params.status,
      statusNote: params.statusNote || null,
      statusUpdatedBy: userId,
      statusUpdatedAt: new Date(),
    },
  });

  await writeAuditLog({
    organizationId: orgId,
    userId,
    action: "finding.status_changed",
    resource: "finding",
    resourceId: finding.id,
    details: {
      from: existing.status,
      to: params.status,
      note: params.statusNote || null,
      title: finding.title,
      severity: finding.severity,
      scanId: finding.scanId,
      ...(params.via ? { via: params.via } : {}),
    },
    ipAddress: params.ipAddress ?? null,
  });

  // Keep the scan's severity totals in step with the new status.
  if (params.status) await recountScanSeverities(finding.scanId).catch(() => undefined);

  // Auto-create suppression rule when marking as false positive
  if (params.status === "FALSE_POSITIVE") {
    try {
      const scanProject = await prisma.finding.findFirst({
        where: { id: findingId },
        select: { scan: { select: { project: { select: { id: true, organizationId: true } } } } },
      });
      await generateSuppressionRule({
        organizationId: orgId,
        projectId: scanProject?.scan.project?.id,
        finding: {
          id: finding.id,
          ruleId: finding.ruleId,
          cweId: finding.cweId,
          scanner: finding.scanner,
          filePath: finding.filePath,
          title: finding.title,
          snippet: finding.snippet,
        },
        reason: params.statusNote || "Marked as false positive",
        userId,
        source: "user",
      });
    } catch {
      // Non-blocking — suppression rule creation failure shouldn't block status update
    }
  }

  const enrichedFinding = enrichFindingWithReport(finding);
  if (!findingHasStoredReport(finding)) {
    await prisma.finding.update({
      where: { id: finding.id },
      data: { metadata: enrichedFinding.metadata as object },
    });
  }
  return { previousStatus: existing.status, finding: enrichedFinding };
}
