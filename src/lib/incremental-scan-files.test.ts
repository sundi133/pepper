import { describe, expect, it } from "vitest";
import {
  applyIncrementalFileFilter,
  isScaManifestPath,
  normalizeRepoPath,
} from "./incremental-scan-files";

describe("incremental-scan-files", () => {
  it("normalizes paths", () => {
    expect(normalizeRepoPath(".\\src\\a.ts")).toBe("src/a.ts");
  });

  it("detects SCA manifest paths", () => {
    expect(isScaManifestPath("package-lock.json")).toBe(true);
    expect(isScaManifestPath("apps/api/package.json")).toBe(true);
    expect(isScaManifestPath("src/MyApp.csproj")).toBe(true);
    expect(isScaManifestPath("src/index.ts")).toBe(false);
  });

  it("filters to changed files and splits SCA vs SAST", () => {
    const all = [
      "src/index.ts",
      "package-lock.json",
      "README.md",
      "src/other.ts",
    ];
    const result = applyIncrementalFileFilter(all, ["src/index.ts", "package-lock.json"]);
    expect(result.usedDiff).toBe(true);
    expect(result.sastAndSecretsFiles).toEqual(["src/index.ts"]);
    expect(result.scaFiles).toEqual(["package-lock.json"]);
    expect(result.changedPathCount).toBe(2);
  });

  it("returns empty scanner lists for empty diff", () => {
    const result = applyIncrementalFileFilter(["src/a.ts"], []);
    expect(result.sastAndSecretsFiles).toEqual([]);
    expect(result.scaFiles).toEqual([]);
    expect(result.usedDiff).toBe(true);
  });

  it("falls back to full file list when diff is unavailable", () => {
    const all = ["src/a.ts", "package.json"];
    const result = applyIncrementalFileFilter(all, null);
    expect(result.usedDiff).toBe(false);
    expect(result.sastAndSecretsFiles).toEqual(all);
    expect(result.scaFiles).toEqual(["package.json"]);
  });
});
