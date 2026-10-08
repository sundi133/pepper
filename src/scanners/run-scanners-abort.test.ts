import { describe, expect, it, vi } from "vitest";

// A secrets-only scan whose pattern scanner never finishes (like a scanner
// stuck on a network call): the scan must still end as soon as it is stopped.
vi.mock("./secrets", () => ({
  secretsPatternScanner: { name: "SECRETS_PATTERN", scan: () => new Promise(() => undefined) },
  secretsLlmScanner: { name: "SECRETS_LLM", scan: async () => [] },
}));

import { runScanners } from "./index";

const ctx = (signal: AbortSignal) =>
  ({
    workDir: "/nonexistent",
    fileList: ["a.ts"],
    scanType: "SECRETS_ONLY",
    orgSettings: { enableLlmSast: false, enableLlmSecrets: false, vulnDbMode: "offline", osvApiUrl: "" },
    signal,
  }) as never;

describe("runScanners and Stop/Cancel", () => {
  it("returns as soon as the scan is aborted, without waiting for a scanner that never finishes", async () => {
    const ac = new AbortController();
    const done = runScanners(ctx(ac.signal));
    setTimeout(() => ac.abort(), 20);
    const result = await Promise.race([done, new Promise((r) => setTimeout(() => r("still waiting"), 2000))]);
    expect(result).not.toBe("still waiting");
  });

  it("returns at once when the scan was already aborted", async () => {
    const ac = new AbortController();
    ac.abort();
    const result = await Promise.race([runScanners(ctx(ac.signal)), new Promise((r) => setTimeout(() => r("still waiting"), 2000))]);
    expect(result).toMatchObject({ dependencies: [] });
  });
});
