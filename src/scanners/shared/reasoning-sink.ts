/**
 * Shared reasoning sink for LLM scanners. Pass `onReasoning` into
 * analyzeWithLlm's options; it streams the model's thinking to the live
 * progress feed (buffered) and accumulates the full trace, which `finalize`
 * persists once via ctx.onReasoning (stored as an AI_REASONING artifact by the
 * processor). Entirely inert when the model emits no reasoning tokens, so
 * non-reasoning models are unaffected.
 */
import { ScanContext } from "../types";

export interface ReasoningSink {
  /** Give this to analyzeWithLlm({ onReasoning }). */
  onReasoning: (delta: string) => void;
  /** Call once when the scanner finishes to persist the full trace. */
  finalize: () => Promise<void>;
}

const LIVE_FLUSH_CHARS = 400;

export function makeReasoningSink(
  ctx: ScanContext,
  scannerName: string,
): ReasoningSink {
  let full = "";
  let buf = "";
  const flushLive = () => {
    if (buf) {
      ctx.onProgress?.(`[${scannerName} reasoning] ${buf}`);
      buf = "";
    }
  };
  return {
    onReasoning: (delta: string) => {
      if (!delta) return;
      full += delta;
      buf += delta;
      if (buf.length >= LIVE_FLUSH_CHARS) flushLive();
    },
    finalize: async () => {
      flushLive();
      if (full.trim()) {
        try {
          await ctx.onReasoning?.(scannerName, full);
        } catch {
          /* storage is best-effort; never fail the scan over it */
        }
      }
    },
  };
}
