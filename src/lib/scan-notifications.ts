import { prisma } from "@/lib/prisma";

export type ScanNotificationType =
  | "SCAN_QUEUED"
  | "SCAN_COMPLETED"
  | "SCAN_FAILED"
  | "SCAN_CANCELLED"
  | "SCAN_STOPPED"
  | "SCAN_PAUSED"
  | "SCAN_RESUMED";

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
}): Promise<void> {
  const { title, body } = COPY[params.type](params.projectName);
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
      project: { select: { name: true, organizationId: true } },
    },
  });
  if (!scan?.project) return;

  let bodySuffix = extra?.bodySuffix;
  if (type === "SCAN_COMPLETED" && scan.gateResult === "FAILED") {
    bodySuffix = "Build gate did not pass.";
  }
  if (type === "SCAN_FAILED" && scan.errorMessage) {
    bodySuffix = scan.errorMessage.slice(0, 200);
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
