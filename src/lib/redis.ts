import IORedis from "ioredis";
import { normalizeLocalhostToIPv4 } from "@/lib/db-url";

const globalForRedis = globalThis as unknown as {
  redis: IORedis | undefined;
};

function redisUrl(): string {
  return normalizeLocalhostToIPv4(
    process.env.REDIS_URL || "redis://127.0.0.1:6379",
  );
}

function createRedis(): IORedis {
  return new IORedis(redisUrl(), {
    maxRetriesPerRequest: null,
    lazyConnect: true,
  });
}

// Lazy singleton — only connects when first accessed at runtime
export const redis = new Proxy({} as IORedis, {
  get(_target, prop) {
    if (!globalForRedis.redis) {
      globalForRedis.redis = createRedis();
    }
    return Reflect.get(globalForRedis.redis, prop);
  },
});

export const redisConnection = {
  get host() {
    return new URL(redisUrl()).hostname;
  },
  get port() {
    return parseInt(new URL(redisUrl()).port || "6379", 10);
  },
};
