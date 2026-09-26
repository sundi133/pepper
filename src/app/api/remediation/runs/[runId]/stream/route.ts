import { NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import {
  TERMINAL_RUN_STATUSES,
  type RemediationRunStatus,
} from "@/lib/remediation/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const POLL_MS = 400;
const HEARTBEAT_MS = 15_000;
const BATCH = 200;

/**
 * GET /api/remediation/runs/[runId]/stream — Server-Sent Events tail of a
 * run's event log. Each event carries `id: <seq>` so EventSource resumes from
 * `Last-Event-ID` after a reconnect; `?after=<seq>` does the same explicitly.
 * Emits `event: end` once the run is finished and fully flushed.
 */
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ runId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) return new Response("No organization", { status: 403 });

  const { runId } = await params;
  const run = await prisma.remediationRun.findFirst({
    where: { id: runId, organizationId: orgId },
    select: { id: true },
  });
  if (!run) return new Response("Run not found", { status: 404 });

  const resumeFrom =
    req.headers.get("last-event-id") ?? new URL(req.url).searchParams.get("after");
  let lastSeq = Math.max(0, Number.parseInt(resumeFrom ?? "0", 10) || 0);

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      const close = () => {
        if (closed) return;
        closed = true;
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      };
      req.signal.addEventListener("abort", close);
      const write = (chunk: string) => {
        if (!closed) controller.enqueue(encoder.encode(chunk));
      };

      write("retry: 2000\n\n");
      let lastBeat = Date.now();

      try {
        while (!closed) {
          const events = await prisma.remediationEvent.findMany({
            where: { runId, seq: { gt: lastSeq } },
            orderBy: { seq: "asc" },
            take: BATCH,
          });
          for (const e of events) {
            lastSeq = e.seq;
            const payload = {
              ...((e.data as Record<string, unknown>) ?? {}),
              type: e.type,
              seq: e.seq,
              at: e.createdAt.toISOString(),
            };
            write(`id: ${e.seq}\ndata: ${JSON.stringify(payload)}\n\n`);
          }
          if (events.length === BATCH) continue;

          const current = await prisma.remediationRun.findUnique({
            where: { id: runId },
            select: { status: true },
          });
          const status = current?.status as RemediationRunStatus | undefined;
          if (!status || TERMINAL_RUN_STATUSES.has(status)) {
            // One last drain in case the worker wrote after our query.
            const tail = await prisma.remediationEvent.count({
              where: { runId, seq: { gt: lastSeq } },
            });
            if (tail === 0) {
              write(`event: end\ndata: ${JSON.stringify({ status: status ?? "FAILED" })}\n\n`);
              break;
            }
            continue;
          }

          if (Date.now() - lastBeat > HEARTBEAT_MS) {
            write(": keep-alive\n\n");
            lastBeat = Date.now();
          }
          await new Promise((r) => setTimeout(r, POLL_MS));
        }
      } catch (e) {
        write(
          `event: stream_error\ndata: ${JSON.stringify({ message: e instanceof Error ? e.message : "stream failed" })}\n\n`,
        );
      } finally {
        close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
