/**
 * Persists a run's progress events in order. The worker is the only writer
 * for a run, so sequence numbers are assigned in-process. Streamed analysis
 * text is coalesced so a token-by-token LLM stream becomes a few writes per
 * second instead of hundreds.
 */
import { prisma } from "@/lib/prisma";
import { Prisma } from "@/generated/prisma/client";
import type { RemediationEventPayload } from "./types";

const DELTA_FLUSH_MS = 350;
const DELTA_FLUSH_CHARS = 1_500;

export class RemediationEventSink {
  private seq: number;
  private pendingDelta: { itemId: string; text: string } | null = null;
  private lastDeltaFlush = 0;
  private chain: Promise<void> = Promise.resolve();

  private constructor(private readonly runId: string, startSeq: number) {
    this.seq = startSeq;
  }

  static async open(runId: string): Promise<RemediationEventSink> {
    const last = await prisma.remediationEvent.findFirst({
      where: { runId },
      orderBy: { seq: "desc" },
      select: { seq: true },
    });
    return new RemediationEventSink(runId, last?.seq ?? 0);
  }

  private write(payload: RemediationEventPayload): Promise<void> {
    const seq = ++this.seq;
    const { type, ...rest } = payload;
    const itemId = "itemId" in payload ? payload.itemId : null;
    this.chain = this.chain.then(async () => {
      try {
        await prisma.remediationEvent.create({
          data: {
            runId: this.runId,
            seq,
            itemId,
            type,
            data: rest as unknown as Prisma.InputJsonValue,
          },
        });
      } catch (e) {
        console.error("[remediation] failed to persist event:", (e as Error).message);
      }
    });
    return this.chain;
  }

  private async flushDelta(): Promise<void> {
    const pending = this.pendingDelta;
    if (!pending || !pending.text) return;
    this.pendingDelta = null;
    this.lastDeltaFlush = Date.now();
    await this.write({ type: "analysis_delta", itemId: pending.itemId, text: pending.text });
  }

  async emit(payload: RemediationEventPayload): Promise<void> {
    await this.flushDelta();
    await this.write(payload);
  }

  /** Buffer streamed analysis text; flushes on time/size thresholds. */
  async delta(itemId: string, text: string): Promise<void> {
    if (this.pendingDelta && this.pendingDelta.itemId !== itemId) {
      await this.flushDelta();
    }
    if (!this.pendingDelta) this.pendingDelta = { itemId, text: "" };
    this.pendingDelta.text += text;
    if (
      Date.now() - this.lastDeltaFlush >= DELTA_FLUSH_MS ||
      this.pendingDelta.text.length >= DELTA_FLUSH_CHARS
    ) {
      await this.flushDelta();
    }
  }

  async close(): Promise<void> {
    await this.flushDelta();
    await this.chain;
  }
}
