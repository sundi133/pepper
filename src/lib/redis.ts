import IORedis from "ioredis";

const globalForRedis = globalThis as unknown as {
  redis: IORedis | undefined;
};

function createRedis(): IORedis {
  const client = new IORedis(process.env.REDIS_URL || "redis://localhost:6379", {
    maxRetriesPerRequest: null,
    lazyConnect: true,
    connectTimeout: 15000,
    retryStrategy(times) {
      return Math.min(times * 500, 5000);
    },
  });
  client.on("error", (err) => {
    console.error("[redis] connection error:", err.message);
  });
  return client;
}

function parseRedisConnection(urlString: string) {
  const url = new URL(urlString);
  const isTls = url.protocol === "rediss:";
  return {
    host: url.hostname,
    port: parseInt(url.port || "6379", 10),
    username: decodeURIComponent(url.username || "default"),
    password: url.password ? decodeURIComponent(url.password) : undefined,
    tls: isTls ? { rejectUnauthorized: false } : undefined,
    maxRetriesPerRequest: null as null,
    connectTimeout: 15000,
    retryStrategy(times: number) {
      return Math.min(times * 500, 5000);
    },
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
