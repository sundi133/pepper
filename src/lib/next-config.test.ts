import { afterEach, describe, expect, it, vi } from "vitest";
import { maxUploadMb, proxyBodySizeLimit } from "./upload-limits";

// next.config.ts repeats the upload-limit parsing (it cannot import project
// modules); these keep it in step with src/lib/upload-limits.ts.
async function loadNextConfig() {
  vi.resetModules();
  return (await import("../../next.config")).default;
}

describe("next.config upload limit", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  for (const raw of [undefined, "", "100", "1024", " 750 ", "250.9", "0", "-1", "abc"]) {
    it(`matches upload-limits for MAX_UPLOAD_MB=${JSON.stringify(raw)}`, async () => {
      vi.stubEnv("MAX_UPLOAD_MB", raw);
      const config = await loadNextConfig();
      expect(config.env?.MAX_UPLOAD_MB).toBe(String(maxUploadMb(raw)));
      expect(config.experimental?.proxyClientMaxBodySize).toBe(proxyBodySizeLimit(raw));
    });
  }

  it("defaults to 500 MB with a 550 MB body buffer", async () => {
    vi.stubEnv("MAX_UPLOAD_MB", undefined);
    const config = await loadNextConfig();
    expect(config.env?.MAX_UPLOAD_MB).toBe("500");
    expect(config.experimental?.proxyClientMaxBodySize).toBe("550mb");
  });
});
