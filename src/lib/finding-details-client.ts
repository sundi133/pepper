/**
 * Browser side of POST /api/findings/:id/generate-details. The route answers
 * 202 while the model is still writing (it keeps going and saves the result),
 * so this retries a few times before giving up.
 */
export type FindingDetailsResult<T> =
  | { ok: true; details: T }
  | { ok: false; error: string; pending?: boolean };

const RETRY_DELAY_MS = 15_000;
const MAX_ATTEMPTS = 4;

function wait(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new DOMException("Aborted", "AbortError"));
      },
      { once: true },
    );
  });
}

export async function requestGeneratedDetails<T = Record<string, unknown>>(
  findingId: string,
  opts: { signal?: AbortSignal; regenerate?: boolean } = {},
): Promise<FindingDetailsResult<T>> {
  const url = `/api/findings/${findingId}/generate-details${opts.regenerate ? "?regenerate=1" : ""}`;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    let res: Response;
    try {
      // Only the first attempt may regenerate; retries pick up its result.
      res = await fetch(attempt === 1 ? url : `/api/findings/${findingId}/generate-details`, {
        method: "POST",
        signal: opts.signal,
      });
    } catch (e) {
      if ((e as Error).name === "AbortError") throw e;
      return { ok: false, error: "Couldn't reach the server" };
    }
    if (res.status === 202) {
      if (attempt === MAX_ATTEMPTS) {
        return { ok: false, pending: true, error: "AI details are still being written. Check back shortly." };
      }
      const retryAfter = Number(res.headers.get("Retry-After"));
      await wait(Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : RETRY_DELAY_MS, opts.signal);
      continue;
    }
    const body = (await res.json().catch(() => null)) as (T & { error?: string }) | null;
    if (!res.ok || !body) {
      return { ok: false, error: body?.error || `AI details failed (${res.status})` };
    }
    return { ok: true, details: body as T };
  }
  return { ok: false, error: "AI details failed" };
}
