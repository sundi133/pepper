import { describe, expect, it } from "vitest";
import { isTestLikePath } from "./test-paths";
import { applyQualityGates } from "@/scanners/shared/quality-gates";
import type { RawFinding } from "@/scanners/types";

describe("isTestLikePath", () => {
  it("still recognises test, fixture, example and demo code", () => {
    for (const p of [
      "tests/test_api.py",
      "src/test/java/com/acme/LoginTest.java",
      "web/__tests__/login.tsx",
      "src/login.test.ts",
      "src/login.spec.js",
      "fixtures/users.json",
      "examples/basic/app.js",
      "demo/server.go",
      "sample/index.php",
      "src\\test\\Foo.cs",
    ]) {
      expect(isTestLikePath(p), p).toBe(true);
    }
  });

  it("treats package paths inside compiled artifacts and Maven/Gradle main sources as production code", () => {
    for (const p of [
      "search-app.jar!/com/example/Search.java",
      "app.ear!/web.war!/WEB-INF/classes/com/example/demo/Login.java",
      "mobile/app-release.apk!/com/example/mobile/LoginActivity.java",
      "src/main/java/com/example/demo/UserController.java",
      "service/src/main/kotlin/com/example/Billing.kt",
    ]) {
      expect(isTestLikePath(p), p).toBe(false);
    }
  });

  it("ignores empty paths", () => {
    expect(isTestLikePath(undefined)).toBe(false);
    expect(isTestLikePath("")).toBe(false);
  });
});

describe("quality gates on compiled-code paths", () => {
  // The finding the live check lost: confirmed SQL injection at 0.8 in a decompiled JAR.
  const f = (filePath: string): RawFinding => ({
    scanner: "SAST_LLM",
    severity: "HIGH",
    title: "SQL injection via string-concatenated query in Search.find",
    description: "Fix: use a PreparedStatement.",
    filePath,
    startLine: 11,
    cweId: "CWE-89",
    confidence: 0.8,
    metadata: { remediation: "Use PreparedStatement" },
  });

  it("keeps it inside a compiled artifact and under src/main", () => {
    expect(applyQualityGates([f("search-app.jar!/com/example/Search.java")])).toHaveLength(1);
    expect(applyQualityGates([f("src/main/java/com/example/Search.java")])).toHaveLength(1);
  });

  it("still holds real test code to the higher bar", () => {
    expect(applyQualityGates([f("src/test/java/com/example/SearchTest.java")])).toHaveLength(0);
  });
});
