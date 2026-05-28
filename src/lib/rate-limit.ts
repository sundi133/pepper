import { redis } from "./redis";

export type RateLimitResult = {
  /** True when the caller has exceeded `max` within the window. */
  limited: boolean;
  /** Milliseconds until the current window resets. */
  resetMs: number;
};

type Options = { windowMs: number; max: number };

// Per-instance fallback, used only when Redis is unavailable so a Redis
// outage degrades to local limiting rather than disabling protection.
const memStore = new Map<string, { count: number; resetAt: number }>();

function memCheck(key: string, { windowMs, max }: Options): RateLimitResult {
  const now = Date.now();
  const entry = memStore.get(key);
  if (!entry || now > entry.resetAt) {
    memStore.set(key, { count: 1, resetAt: now + windowMs });
    return { limited: false, resetMs: windowMs };
  }
  entry.count++;
  return { limited: entry.count > max, resetMs: entry.resetAt - now };
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error("redis-timeout")), ms),
    ),
  ]);
}

/**
 * Fixed-window rate limiter, shared across instances via Redis.
 * Falls back to a per-instance in-memory counter if Redis is unreachable.
 */
export async function checkRateLimit(
  key: string,
  opts: Options,
): Promise<RateLimitResult> {
  const redisKey = `ratelimit:${key}`;
  try {
    const count = await withTimeout(redis.incr(redisKey), 1000);
    if (count === 1) {
      await withTimeout(redis.pexpire(redisKey, opts.windowMs), 1000);
      return { limited: false, resetMs: opts.windowMs };
    }
    let ttl = await withTimeout(redis.pttl(redisKey), 1000);
    if (ttl < 0) {
      await withTimeout(redis.pexpire(redisKey, opts.windowMs), 1000);
      ttl = opts.windowMs;
    }
    return { limited: count > opts.max, resetMs: ttl };
  } catch {
    return memCheck(key, opts);
  }
}
