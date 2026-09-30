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
    tls: isTls ? { rejectUnauthorized: false, servername: url.hostname } : undefined,
    maxRetriesPerRequest: null as null,
    connectTimeout: 15000,
    enableOfflineQueue: true,
    retryStrategy(times: number) {
      return Math.min(times * 500, 5000);
    },
  };
}

function redisClient(): IORedis {
  if (!globalForRedis.redis) {
    globalForRedis.redis = createRedis();
  }
  return globalForRedis.redis;
}

// Lazy singleton — only connects when first accessed at runtime.
// Methods are bound to the real client: called through the proxy, ioredis
// would otherwise write its connection state (this.condition, this.status)
// onto the proxy's empty target and then crash reading it back
// ("Cannot read properties of undefined (reading 'auth')").
export const redis = new Proxy({} as IORedis, {
  get(_target, prop) {
    const client = redisClient();
    const value = Reflect.get(client, prop, client);
    return typeof value === "function" ? value.bind(client) : value;
  },
});

export const redisConnection = {
  ...parseRedisConnection(process.env.REDIS_URL || "redis://localhost:6379"),
};
