import { prisma } from "@/lib/prisma";

export type ScanNotificationType =
  | "SCAN_QUEUED"
  | "SCAN_COMPLETED"
  | "SCAN_FAILED"
  | "SCAN_CANCELLED"
  | "SCAN_STOPPED"
  | "SCAN_PAUSED"
  | "SCAN_RESUMED"
  | "SCAN_GATE_FAILED";

/** Notification types the page knows how to show (stored as a plain string). */
export type NotificationType = ScanNotificationType | "SIGNING_FAILED";

export interface ScanSeverityCounts {
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  newFindingCount: number;
}

/**
 * Title and summary for a finished scan, leading with what needs attention:
 * "Scan completed: 2 critical issues" / "…: 2 critical, 5 high, 1 low (3 new)".
 */
export function completionCopy(
  projectName: string,
  counts: ScanSeverityCounts,
  gateFailed: boolean,
): { title: string; body: string } {
  const parts = (
    [
      [counts.criticalCount, "critical"],
      [counts.highCount, "high"],
      [counts.mediumCount, "medium"],
      [counts.lowCount, "low"],
    ] as const
  )
    .filter(([n]) => n > 0)
    .map(([n, label]) => `${n} ${label}`);
  const summary =
    parts.length === 0
      ? "no open issues found"
      : `${parts.join(", ")}${counts.newFindingCount > 0 ? ` (${counts.newFindingCount} new)` : ""}`;

  if (gateFailed) {
    return {
      title: `Build gate failed: ${projectName}`,
      body: `Scan of ${projectName} finished with ${summary}. The build gate did not pass.`,
    };
  }
  const urgent =
    counts.criticalCount > 0
      ? `${counts.criticalCount} critical issue${counts.criticalCount === 1 ? "" : "s"}`
      : counts.highCount > 0
        ? `${counts.highCount} high issue${counts.highCount === 1 ? "" : "s"}`
        : null;
  return {
    title: urgent ? `Scan completed: ${urgent}` : "Scan completed",
    body: `Security scan finished for ${projectName}: ${summary}.`,
  };
}

const COPY: Record<
  ScanNotificationType,
  (projectName: string) => { title: string; body: string }
> = {
  SCAN_QUEUED: (p) => ({
    title: "Scan queued",
    body: `Security scan queued for ${p}.`,
  }),
  SCAN_COMPLETED: (p) => ({
    title: "Scan completed",
    body: `Security scan finished for ${p}.`,
  }),
  SCAN_FAILED: (p) => ({
    title: "Scan failed",
    body: `Security scan failed for ${p}.`,
  }),
  SCAN_CANCELLED: (p) => ({
    title: "Scan cancelled",
    body: `Security scan was cancelled for ${p}.`,
  }),
  SCAN_STOPPED: (p) => ({
    title: "Scan stopped",
    body: `Security scan was stopped for ${p}. Partial results may be available.`,
  }),
  SCAN_PAUSED: (p) => ({
    title: "Scan paused",
    body: `Security scan paused for ${p}.`,
  }),
  SCAN_RESUMED: (p) => ({
    title: "Scan resumed",
    body: `Security scan resumed for ${p}.`,
  }),
  SCAN_GATE_FAILED: (p) => ({
    title: `Build gate failed: ${p}`,
    body: `The build gate did not pass for ${p}.`,
  }),
};

async function recipientUserIds(
  organizationId: string,
  triggeredBy: string | null | undefined,
  actorUserId?: string,
): Promise<string[]> {
  const ids = new Set<string>();
  if (actorUserId) ids.add(actorUserId);
  if (triggeredBy && triggeredBy !== "scheduler") {
    ids.add(triggeredBy);
  }
  if (triggeredBy === "scheduler" || ids.size === 0) {
    const members = await prisma.orgMember.findMany({
      where: { organizationId },
      select: { userId: true },
    });
    for (const m of members) ids.add(m.userId);
  }
  return [...ids];
}

export async function createScanNotification(params: {
  type: ScanNotificationType;
  organizationId: string;
  scanId: string;
  projectName: string;
  triggeredBy?: string | null;
  actorUserId?: string;
  bodySuffix?: string;
  /** Replaces the default copy for this type. */
  copy?: { title: string; body: string };
}): Promise<void> {
  const { title, body } = params.copy ?? COPY[params.type](params.projectName);
  const fullBody = params.bodySuffix ? `${body} ${params.bodySuffix}` : body;
  const users = await recipientUserIds(
    params.organizationId,
    params.triggeredBy,
    params.actorUserId,
  );

  if (users.length === 0) return;

  await prisma.notification.createMany({
    data: users.map((userId) => ({
      userId,
      organizationId: params.organizationId,
      type: params.type,
      title,
      body: fullBody,
      scanId: params.scanId,
    })),
  });
}

export async function createScanQueuedNotification(params: {
  userId: string;
  organizationId: string;
  scanId: string;
  projectName: string;
}): Promise<void> {
  await createScanNotification({
    type: "SCAN_QUEUED",
    organizationId: params.organizationId,
    scanId: params.scanId,
    projectName: params.projectName,
    actorUserId: params.userId,
  });
}

export async function notifyScanLifecycleFromWorker(
  scanId: string,
  type: Extract<
    ScanNotificationType,
    "SCAN_COMPLETED" | "SCAN_FAILED" | "SCAN_CANCELLED" | "SCAN_STOPPED"
  >,
  extra?: { bodySuffix?: string },
): Promise<void> {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      triggeredBy: true,
      gateResult: true,
      errorMessage: true,
      criticalCount: true,
      highCount: true,
      mediumCount: true,
      lowCount: true,
      newFindingCount: true,
      project: { select: { name: true, organizationId: true } },
    },
  });
  if (!scan?.project) return;

  let bodySuffix = extra?.bodySuffix;
  if (type === "SCAN_FAILED" && scan.errorMessage) {
    bodySuffix = scan.errorMessage.slice(0, 200);
  }

  if (type === "SCAN_COMPLETED") {
    const gateFailed = scan.gateResult === "FAILED";
    await createScanNotification({
      type: gateFailed ? "SCAN_GATE_FAILED" : "SCAN_COMPLETED",
      organizationId: scan.project.organizationId,
      scanId,
      projectName: scan.project.name,
      triggeredBy: scan.triggeredBy,
      bodySuffix,
      copy: completionCopy(scan.project.name, scan, gateFailed),
    });
    return;
  }

  await createScanNotification({
    type,
    organizationId: scan.project.organizationId,
    scanId,
    projectName: scan.project.name,
    triggeredBy: scan.triggeredBy,
    bodySuffix,
  });
}

/**
 * Tell the org's Security and Admin members that a scan's artifacts weren't
 * signed: an unsigned SBOM handed to a customer is a silent compliance gap.
 */
export async function notifySigningFailed(params: {
  organizationId: string;
  scanId: string;
  reason: string;
}): Promise<void> {
  const [members, scan] = await Promise.all([
    prisma.orgMember.findMany({
      where: { organizationId: params.organizationId, role: { in: ["ADMIN", "SECURITY"] } },
      select: { userId: true },
    }),
    prisma.scan.findUnique({
      where: { id: params.scanId },
      select: { project: { select: { name: true } } },
    }),
  ]);
  if (members.length === 0) return;
  const projectName = scan?.project?.name ?? "a repository";
  await prisma.notification.createMany({
    data: members.map((m) => ({
      userId: m.userId,
      organizationId: params.organizationId,
      type: "SIGNING_FAILED",
      title: "Artifact signing failed",
      body: `SBOMs for ${projectName} were not signed: ${params.reason.slice(0, 200)}`,
      scanId: params.scanId,
    })),
  });
}

/** Read notifications are kept this long; unread ones a bit longer. */
export const NOTIFICATION_RETENTION_DAYS = { read: 30, unread: 90 } as const;

/** Delete notifications past retention. Returns the number removed. */
export async function purgeOldNotifications(now = new Date()): Promise<number> {
  const day = 24 * 60 * 60 * 1000;
  const readCutoff = new Date(now.getTime() - NOTIFICATION_RETENTION_DAYS.read * day);
  const unreadCutoff = new Date(now.getTime() - NOTIFICATION_RETENTION_DAYS.unread * day);
  const result = await prisma.notification.deleteMany({
    where: {
      OR: [
        { read: true, createdAt: { lt: readCutoff } },
        { createdAt: { lt: unreadCutoff } },
      ],
    },
  });
  return result.count;
}

export async function notifyScanLifecycleFromApi(params: {
  scanId: string;
  organizationId: string;
  actorUserId: string;
  type: Extract<
    ScanNotificationType,
    "SCAN_CANCELLED" | "SCAN_STOPPED" | "SCAN_PAUSED" | "SCAN_RESUMED" | "SCAN_QUEUED"
  >;
}): Promise<void> {
  const scan = await prisma.scan.findUnique({
    where: { id: params.scanId },
    select: {
      triggeredBy: true,
      project: { select: { name: true } },
    },
  });
  if (!scan?.project) return;

  await createScanNotification({
    type: params.type,
    organizationId: params.organizationId,
    scanId: params.scanId,
    projectName: scan.project.name,
    triggeredBy: scan.triggeredBy,
    actorUserId: params.actorUserId,
  });
}
