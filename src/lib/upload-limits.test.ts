import { describe, expect, it } from "vitest";
import { DEFAULT_MAX_UPLOAD_MB, maxUploadBytes, maxUploadMb, proxyBodySizeLimit } from "./upload-limits";

describe("maxUploadMb", () => {
  it("defaults to 500 MB", () => {
    expect(DEFAULT_MAX_UPLOAD_MB).toBe(500);
    expect(maxUploadMb(undefined)).toBe(500);
    expect(maxUploadMb("")).toBe(500);
  });

  it("reads MAX_UPLOAD_MB", () => {
    expect(maxUploadMb("1024")).toBe(1024);
    expect(maxUploadMb(" 100 ")).toBe(100);
    expect(maxUploadMb("250.9")).toBe(250);
  });

  it("falls back on invalid values", () => {
    for (const raw of ["0", "-5", "abc", "0.5", "Infinity"]) {
      expect(maxUploadMb(raw)).toBe(500);
    }
  });
});

describe("maxUploadBytes", () => {
  it("converts megabytes to bytes", () => {
    expect(maxUploadBytes("100")).toBe(100 * 1024 * 1024);
    expect(maxUploadBytes(undefined)).toBe(500 * 1024 * 1024);
  });
});

describe("proxyBodySizeLimit", () => {
  it("leaves headroom above the upload limit for the multipart body", () => {
    expect(proxyBodySizeLimit("100")).toBe("150mb");
    expect(proxyBodySizeLimit(undefined)).toBe("550mb");
    expect(proxyBodySizeLimit("2000")).toBe("2200mb");
  });
});
