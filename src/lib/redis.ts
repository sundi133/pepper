import IORedis from "ioredis";

const globalForRedis = globalThis as unknown as {
  redis: IORedis | undefined;
};

function createRedis(): IORedis {
  return new IORedis(process.env.REDIS_URL || "redis://localhost:6379", {
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
    return new URL(process.env.REDIS_URL || "redis://localhost:6379").hostname;
  },
  get port() {
    return parseInt(
      new URL(process.env.REDIS_URL || "redis://localhost:6379").port || "6379"
    );
  },
};
