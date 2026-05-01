import type { RawFinding } from "./types";

export type { ScanEvent } from "./types";

const MAX_META_LEN = 6000;

/** Shrink finding for JSON/event payloads (avoid huge metadata in DB progress). */
export function sanitizeFindingForEvent(f: RawFinding): RawFinding {
  let meta = f.metadata;
  if (meta && typeof meta === "object") {
    const s = JSON.stringify(meta);
    if (s.length > MAX_META_LEN) {
      meta = {
        _truncated: true,
        preview: s.slice(0, 2000),
      } as Record<string, unknown>;
    }
  }
  return {
    ...f,
    description:
      f.description.length > 8000
        ? `${f.description.slice(0, 8000)}…`
        : f.description,
    snippet:
      f.snippet && f.snippet.length > 4000
        ? `${f.snippet.slice(0, 4000)}…`
        : f.snippet,
    metadata: meta as Record<string, unknown> | undefined,
  };
}
