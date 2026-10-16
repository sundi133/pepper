import { describe, expect, it } from "vitest";
import type { RawFinding } from "@/scanners/types";
import { DecompiledPathMap } from "./path-mapping";
import { decompiledOriginOf, decompilerLabel, isDecompiledFinding } from "./finding-origin";
import {
  compiledUploadObjectKey,
  isCompiledArtifactUpload,
  safeArtifactFileName,
  uploadedArtifactName,
} from "./upload";

const map = new DecompiledPathMap([
  { artifact: "release/app.apk", outDir: "__decompiled__/1-app.apk", tool: "jadx" },
  { artifact: "app.ear", outDir: "__decompiled__/2-app.ear", tool: "vineflower" },
  { artifact: "app.ear!/web.war", outDir: "__decompiled__/3-web.war", tool: "vineflower" },
  { artifact: "webapp/WEB-INF/classes", outDir: "__decompiled__/4-classes", tool: "vineflower" },
  { artifact: "bin/App.dll", outDir: "__decompiled__/5-App.dll", tool: "ilspycmd" },
]);

const finding = (filePath: string, extra: Partial<RawFinding> = {}): RawFinding => ({
  scanner: "SAST_PATTERN",
  severity: "HIGH",
  title: "SQL injection",
  description: "d",
  filePath,
  startLine: 42,
  ...extra,
});

describe("DecompiledPathMap", () => {
  it("maps decompiled files to artifact!/file", () => {
    expect(map.resolve("__decompiled__/1-app.apk/com/example/Login.java")?.displayPath).toBe(
      "release/app.apk!/com/example/Login.java",
    );
    expect(map.resolve("__decompiled__/3-web.war/WEB-INF/classes/com/x/A.java")?.displayPath).toBe(
      "app.ear!/web.war!/WEB-INF/classes/com/x/A.java",
    );
    expect(map.resolve("__decompiled__/4-classes/com/acme/Login.java")?.displayPath).toBe(
      "webapp/WEB-INF/classes!/com/acme/Login.java",
    );
    expect(map.resolve("__decompiled__/5-App.dll/MyApp/Services/Login.cs")?.displayPath).toBe(
      "bin/App.dll!/MyApp/Services/Login.cs",
    );
    // Same mapping from OpenGrep's "./"-prefixed paths and Windows separators.
    expect(map.resolve("./__decompiled__/1-app.apk/AndroidManifest.xml")?.displayPath).toBe("release/app.apk!/AndroidManifest.xml");
    expect(map.resolve("__decompiled__\\1-app.apk\\res\\values\\strings.xml")?.innerPath).toBe("res/values/strings.xml");
  });

  it("leaves ordinary source files alone", () => {
    expect(map.resolve("src/main/java/Login.java")).toBeNull();
    expect(map.resolve("__decompiled__/1-app.apk")).toBeNull();
    expect(map.resolve("__decompiled__/1-app.apkx/A.java")).toBeNull();
    expect(map.resolve(undefined)).toBeNull();
  });

  it("rewrites a finding and marks it as found in compiled code", () => {
    const mapped = map.mapFinding(finding("__decompiled__/1-app.apk/com/example/Login.java", { metadata: { engine: "opengrep" } }));
    expect(mapped.filePath).toBe("release/app.apk!/com/example/Login.java");
    expect(mapped.startLine).toBe(42);
    expect(mapped.metadata).toEqual({
      engine: "opengrep",
      decompiledFrom: "release/app.apk",
      decompiledFile: "com/example/Login.java",
      decompiledPath: "__decompiled__/1-app.apk/com/example/Login.java",
      decompiler: "jadx",
    });
  });

  it("returns findings outside decompiled code unchanged", () => {
    const f = finding("src/a.ts", { metadata: { x: 1 } });
    expect(map.mapFinding(f)).toBe(f);
    expect(new DecompiledPathMap().mapFinding(f)).toBe(f);
    const noPath = finding("", { filePath: undefined });
    expect(map.mapFinding(noPath)).toBe(noPath);
  });
});

describe("finding origin helpers (UI, exports)", () => {
  it("reads the compiled-code marker", () => {
    const mapped = map.mapFinding(finding("__decompiled__/5-App.dll/MyApp/Login.cs"));
    expect(decompiledOriginOf(mapped.metadata)).toEqual({
      artifact: "bin/App.dll",
      file: "MyApp/Login.cs",
      decompiler: "ilspycmd",
      decompiledPath: "__decompiled__/5-App.dll/MyApp/Login.cs",
    });
    expect(isDecompiledFinding(mapped)).toBe(true);
    expect(isDecompiledFinding({ filePath: "app.jar!/A.java" })).toBe(true);
    expect(isDecompiledFinding({ filePath: "src/A.java", metadata: { engine: "x" } })).toBe(false);
    expect(decompiledOriginOf(null)).toBeNull();
    expect(decompiledOriginOf(["x"])).toBeNull();
    expect(decompilerLabel("ilspycmd")).toBe("ILSpy");
    expect(decompilerLabel("vineflower")).toBe("Vineflower");
  });
});

describe("single compiled-artifact uploads", () => {
  it("accepts compiled artifacts and keeps a safe name", () => {
    expect(isCompiledArtifactUpload("App-Release.APK")).toBe(true);
    expect(isCompiledArtifactUpload("service.war")).toBe(true);
    expect(isCompiledArtifactUpload("source.zip")).toBe(false);
    expect(isCompiledArtifactUpload("Main.class")).toBe(false);
    expect(safeArtifactFileName("C:\\builds\\My App (1).DLL")).toBe("My_App__1_.dll");
    expect(safeArtifactFileName("../../etc/passwd.jar")).toBe("passwd.jar");
    expect(safeArtifactFileName("..jar")).toBe("artifact.jar");
    expect(compiledUploadObjectKey("scan1", "app-release.apk")).toBe("scans/scan1/compiled/app-release.apk");
  });

  it("recognises the object key in the worker", () => {
    expect(uploadedArtifactName("scans/scan1/compiled/app-release.apk")).toBe("app-release.apk");
    expect(uploadedArtifactName("scans/scan1/source.zip")).toBeNull();
    expect(uploadedArtifactName("scans/scan1/compiled/../x.apk")).toBeNull();
    expect(uploadedArtifactName("https://github.com/a/b")).toBeNull();
    expect(uploadedArtifactName(null)).toBeNull();
  });
});
