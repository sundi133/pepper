import { prisma } from "@/lib/prisma";

export async function createScanQueuedNotification(params: {
  userId: string;
  organizationId: string;
  scanId: string;
  projectName: string;
}): Promise<void> {
  await prisma.notification.create({
    data: {
      userId: params.userId,
      organizationId: params.organizationId,
      type: "SCAN_QUEUED",
      title: "Scan initiated",
      body: `Security scan started for ${params.projectName}.`,
      scanId: params.scanId,
    },
  });
}
