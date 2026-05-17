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

function parseRedisConnection(urlString: string) {
  const url = new URL(urlString);
  const isTls = url.protocol === "rediss:";
  return {
    host: url.hostname,
    port: parseInt(url.port || "6379", 10),
    username: decodeURIComponent(url.username || "default"),
    password: url.password ? decodeURIComponent(url.password) : undefined,
    tls: isTls ? {} : undefined,
    maxRetriesPerRequest: null as null,
  };
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
  ...parseRedisConnection(process.env.REDIS_URL || "redis://localhost:6379"),
};
