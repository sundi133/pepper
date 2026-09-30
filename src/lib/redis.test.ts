import { describe, expect, it, vi } from "vitest";

// Stand-in for IORedis that, like the real client, keeps connection state on
// `this` and reads it back later from another method.
vi.mock("ioredis", () => ({
  default: class FakeRedis {
    condition?: { auth: string };
    on() {
      return this;
    }
    async set(key: string) {
      this.condition = { auth: "token" }; // what connect() does
      return this.readAuth(key);
    }
    readAuth(key: string) {
      return `${key}:${this.condition!.auth}`;
    }
  },
}));

import { redis } from "./redis";

describe("lazy redis proxy", () => {
  it("runs commands against the real client, so connection state survives", async () => {
    await expect((redis as unknown as { set: (k: string) => Promise<string> }).set("k")).resolves.toBe("k:token");
  });
});
