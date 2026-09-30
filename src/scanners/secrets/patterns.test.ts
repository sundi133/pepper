import { describe, expect, it } from "vitest";
import { isLikelyPlaceholderSecret, isSecretScanCandidate } from "./patterns";

describe("isSecretScanCandidate", () => {
  it("covers mobile, JVM and .NET config files that used to be skipped", () => {
    for (const f of [
      "ios/App/Info.plist",
      "ios/Config/Release.xcconfig",
      "ios/App/APIClient.m",
      "ios/App/Keys.h",
      "ios/App/Service.swift",
      "android/app/src/main/java/App.kt",
      "android/build.gradle.kts",
      "android/gradle.properties",
      "android/local.properties",
      "src/main/resources/application.properties",
      "Web.config",
      "src/lib/client.mjs",
      "server/config.cjs",
      ".npmrc",
      ".pypirc",
    ]) {
      expect(isSecretScanCandidate(f, "pattern"), f).toBe(true);
      expect(isSecretScanCandidate(f, "llm"), f).toBe(true);
    }
  });

  it("reads all XML with patterns but only credential-bearing XML with the LLM", () => {
    expect(isSecretScanCandidate("app/src/main/res/layout/main.xml", "pattern")).toBe(true);
    expect(isSecretScanCandidate("app/src/main/res/layout/main.xml", "llm")).toBe(false);
    expect(isSecretScanCandidate(".m2/settings.xml", "llm")).toBe(true);
    expect(isSecretScanCandidate("app/src/main/res/values/strings.xml", "llm")).toBe(true);
  });

  it("still skips non-text and unrelated files", () => {
    expect(isSecretScanCandidate("logo.png", "pattern")).toBe(false);
    expect(isSecretScanCandidate("README.md", "pattern")).toBe(false);
  });
});

describe("isLikelyPlaceholderSecret", () => {
  it("keeps the existing placeholder rules", () => {
    expect(isLikelyPlaceholderSecret("AKIAEXAMPLEEXAMPLE12")).toBe(true);
    expect(isLikelyPlaceholderSecret("xxx-aaaaaaaaaaaaaaaa")).toBe(true);
    expect(isLikelyPlaceholderSecret("AKIAQ3ZRT5WJ4N6P2LMB")).toBe(false);
  });
});
