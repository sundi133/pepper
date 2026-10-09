import { describe, it, expect } from "vitest";
import { isScanNoisePath, filterScanNoise } from "./scan-noise-filter";

describe("scan noise filter", () => {
  it("drops tests, fixtures, docs and API collections", () => {
    for (const p of [
      "cypress-tests/cypress/e2e/payments.js",
      "cypress-tests-v2/foo.js",
      "postman/collection-dir/stripe/event.json",
      "api-reference/openapi.json",
      "crates/router/tests/payments.rs",
      "src/app/__tests__/a.ts",
      "src/a.test.ts",
      "pkg/handler_test.go",
      "app/test_views.py",
      "public/vendor.min.js",
      "loadtest/k6/run.js",
      "crates/router/benches/bench.rs",
    ]) {
      expect(isScanNoisePath(p), p).toBe(true);
    }
  });

  it("keeps production code", () => {
    for (const p of [
      "crates/router/src/services/authentication.rs",
      "crates/router/src/routes/payments.rs",
      "src/lib/testing-utils-config.ts",
      "src/contest.ts",
      "Cargo.toml",
      "package.json",
    ]) {
      expect(isScanNoisePath(p), p).toBe(false);
    }
  });

  it("reports how many files were dropped", () => {
    expect(filterScanNoise(["src/a.ts", "tests/a.ts"])).toEqual({ kept: ["src/a.ts"], dropped: 1 });
  });
});
