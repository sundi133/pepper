import { prisma } from "@/lib/prisma";
import type { ScanEvent } from "@/scanners/types";

const MAX_EVENTS = 80;

/**
 * Persist recent scan events into scannerProgress.liveScan for polling clients.
 */
export async function appendScanLiveEvent(
  scanId: string,
  event: ScanEvent,
): Promise<void> {
  try {
    const row = await prisma.scan.findUnique({
      where: { id: scanId },
      select: { scannerProgress: true },
    });
    const sp =
      row?.scannerProgress &&
      typeof row.scannerProgress === "object" &&
      !Array.isArray(row.scannerProgress)
        ? { ...(row.scannerProgress as Record<string, unknown>) }
        : {};

    const prevLive = sp.liveScan as
      | { events?: ScanEvent[]; seq?: number }
      | undefined;
    const seq = (prevLive?.seq ?? 0) + 1;
    const events = [event, ...(prevLive?.events ?? [])].slice(0, MAX_EVENTS);

    sp.liveScan = {
      events,
      seq,
      lastEventType: event.type,
      lastEventAt: event.timestamp,
    };

    await prisma.scan.update({
      where: { id: scanId },
      data: { scannerProgress: sp as object },
    });
  } catch {
    // Live progress is best-effort; scanner execution must not fail because
    // polling metadata could not be persisted under DB load.
  }
}
