import { describe, it, expect } from "vitest";
import { parseRescanBody } from "./scan-types";

/**
 * A rescan previously always reused the original scan's type, so choosing "All"
 * in the UI on a repository last scanned with a narrower mode silently gave the
 * narrower mode again — and therefore no SBOM, VEX or dependency findings.
 */
describe("parseRescanBody", () => {
  it("accepts an empty body and reuses the original scan type", () => {
    // Backwards compatibility: the button used to POST with no body at all.
    expect(parseRescanBody("")).toEqual({ ok: true });
    expect(parseRescanBody("   ")).toEqual({ ok: true });
  });

  it("accepts an explicit FULL rescan", () => {
    expect(parseRescanBody(JSON.stringify({ scanType: "FULL" }))).toEqual({
      ok: true,
      scanType: "FULL",
    });
  });

  it("accepts every scan type the create endpoint accepts", () => {
    for (const t of [
      "FULL",
      "INCREMENTAL",
      "SAST_ONLY",
      "SCA_ONLY",
      "SECRETS_ONLY",
      "IAC_ONLY",
      "ZERO_DAY_ONLY",
      "CONTAINER_ONLY",
      "K8S_ONLY",
    ]) {
      expect(parseRescanBody(JSON.stringify({ scanType: t }))).toEqual({
        ok: true,
        scanType: t,
      });
    }
  });

  it("treats an omitted or null scanType as reuse-the-original", () => {
    expect(parseRescanBody("{}")).toEqual({ ok: true });
    expect(parseRescanBody(JSON.stringify({ scanType: null }))).toEqual({
      ok: true,
    });
  });

  it("rejects an unknown scan type rather than silently ignoring it", () => {
    expect(parseRescanBody(JSON.stringify({ scanType: "EVERYTHING" }))).toEqual({
      ok: false,
      error: "Invalid scanType",
    });
  });

  it("rejects a scan type the create endpoint does not expose", () => {
    // DAST was removed from the product; it must not be revivable via rescan.
    expect(parseRescanBody(JSON.stringify({ scanType: "DAST_ONLY" }))).toEqual({
      ok: false,
      error: "Invalid scanType",
    });
  });

  it("rejects a non-string scan type", () => {
    expect(parseRescanBody(JSON.stringify({ scanType: 5 })).ok).toBe(false);
    expect(parseRescanBody(JSON.stringify({ scanType: ["FULL"] })).ok).toBe(false);
  });

  it("rejects malformed JSON", () => {
    expect(parseRescanBody("{not json")).toEqual({
      ok: false,
      error: "Invalid request body",
    });
  });

  it("rejects a non-object body", () => {
    // An empty body means "reuse the original"; a body that is present but not
    // an object is malformed and rejected rather than silently ignored.
    expect(parseRescanBody('"FULL"').ok).toBe(false);
    expect(parseRescanBody("[]").ok).toBe(false);
    expect(parseRescanBody("null").ok).toBe(false);
    expect(parseRescanBody("5").ok).toBe(false);
  });

  it("ignores unrelated fields", () => {
    expect(
      parseRescanBody(JSON.stringify({ scanType: "SCA_ONLY", nope: true })),
    ).toEqual({ ok: true, scanType: "SCA_ONLY" });
  });
});
