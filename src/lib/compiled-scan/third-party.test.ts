import { describe, expect, it } from "vitest";
import {
  isInDependencyDir,
  isThirdPartyAssembly,
  isThirdPartyPackage,
  packagePathOf,
  vineflowerExcludeRegex,
} from "./third-party";
import { compiledScanConfig, parsePackageList } from "./config";

const defaults = { skipThirdParty: true, excludePackages: [], includePackages: [] };

describe("dependency folders", () => {
  it("recognises dependency folders at any depth", () => {
    for (const p of [
      "WEB-INF/lib/a.jar",
      "app/WEB-INF/lib/a.jar",
      "BOOT-INF/lib/a.jar",
      "lib/a.jar",
      "server/libs/a.jar",
      "node_modules/x/a.jar",
      "packages/Foo.1.0/lib/Foo.dll",
      "home/.m2/repository/a.jar",
      ".gradle/caches/a.jar",
      "vendor/a.jar",
    ]) {
      expect(isInDependencyDir(p), p).toBe(true);
    }
  });

  it("does not treat application folders as dependencies", () => {
    for (const p of ["app.jar", "dist/app.war", "release/app.apk", "src/library/Main.class", "bin/App.dll", "WEB-INF/classes/A.class"]) {
      expect(isInDependencyDir(p), p).toBe(false);
    }
  });
});

describe("third-party packages", () => {
  it("skips well-known library packages, not the application's", () => {
    expect(isThirdPartyPackage("androidx/core/app/A.java", defaults)).toBe(true);
    expect(isThirdPartyPackage("com/google/gson/Gson.java", defaults)).toBe(true);
    expect(isThirdPartyPackage("kotlin/collections/X.java", defaults)).toBe(true);
    expect(isThirdPartyPackage("okhttp3/OkHttpClient.java", defaults)).toBe(true);
    expect(isThirdPartyPackage("WEB-INF/classes/org/apache/commons/X.java", defaults)).toBe(true);
    expect(isThirdPartyPackage("Newtonsoft/Json/JsonConvert.cs", defaults)).toBe(true);
    expect(isThirdPartyPackage("com/example/app/Login.java", defaults)).toBe(false);
    expect(isThirdPartyPackage("WEB-INF/classes/com/example/Login.java", defaults)).toBe(false);
    // Prefixes match whole package segments only.
    expect(isThirdPartyPackage("javaapp/Main.java", defaults)).toBe(false);
    expect(isThirdPartyPackage("com/googlex/Main.java", defaults)).toBe(false);
  });

  it("honours include and exclude overrides", () => {
    const filter = { skipThirdParty: true, includePackages: ["org/apache/myproject"], excludePackages: ["com/acme/generated"] };
    expect(isThirdPartyPackage("org/apache/myproject/Server.java", filter)).toBe(false);
    expect(isThirdPartyPackage("org/apache/commons/Lang.java", filter)).toBe(true);
    expect(isThirdPartyPackage("com/acme/generated/Proto.java", filter)).toBe(true);
    expect(isThirdPartyPackage("com/acme/web/Login.java", filter)).toBe(false);
  });

  it("keeps everything when third-party skipping is off, except explicit excludes", () => {
    const filter = { skipThirdParty: false, includePackages: [], excludePackages: ["com/acme/generated"] };
    expect(isThirdPartyPackage("androidx/core/A.java", filter)).toBe(false);
    expect(isThirdPartyPackage("com/acme/generated/Proto.java", filter)).toBe(true);
  });

  it("strips web and boot class folders before matching", () => {
    expect(packagePathOf("BOOT-INF/classes/com/x/A.java")).toBe("com/x/A.java");
    expect(packagePathOf("WEB-INF/classes/com/x/A.java")).toBe("com/x/A.java");
    expect(packagePathOf("com/x/A.java")).toBe("com/x/A.java");
  });
});

describe("vineflowerExcludeRegex", () => {
  it("matches excluded classes by dotted or slashed name, honouring includes", () => {
    const re = new RegExp(
      vineflowerExcludeRegex({ skipThirdParty: true, includePackages: ["org/apache/myproject"], excludePackages: [] })!,
    );
    expect(re.test("org.apache.commons.Lang")).toBe(true);
    expect(re.test("org/apache/commons/Lang")).toBe(true);
    expect(re.test("com.google.gson.Gson")).toBe(true);
    expect(re.test("org.apache.myproject.Server")).toBe(false);
    expect(re.test("com.example.Login")).toBe(false);
    expect(re.test("javaapp.Main")).toBe(false);
  });

  it("is null when nothing is excluded", () => {
    expect(vineflowerExcludeRegex({ skipThirdParty: false, includePackages: [], excludePackages: [] })).toBeNull();
  });
});

describe("third-party assemblies", () => {
  it("recognises well-known library assemblies", () => {
    for (const n of ["Newtonsoft.Json.dll", "System.Text.Json.dll", "Microsoft.AspNetCore.Mvc.dll", "Serilog.Sinks.File.dll", "AWSSDK.S3.dll"]) {
      expect(isThirdPartyAssembly(n, defaults), n).toBe(true);
    }
    for (const n of ["MyCompany.Api.dll", "App.exe", "Contoso.Web.dll"]) {
      expect(isThirdPartyAssembly(n, defaults), n).toBe(false);
    }
  });
});

describe("compiledScanConfig", () => {
  it("has sensible defaults", () => {
    const c = compiledScanConfig({});
    expect(c.enabled).toBe(true);
    expect(c.maxArtifactBytes).toBe(200 * 1024 * 1024);
    expect(c.maxArtifacts).toBe(25);
    expect(c.maxFiles).toBe(5000);
    expect(c.maxOutputBytes).toBe(200 * 1024 * 1024);
    expect(c.timeoutMs).toBe(600_000);
    expect(c.totalTimeoutMs).toBe(1_800_000);
    expect(c.skipThirdParty).toBe(true);
    expect(c.jadxBin).toBe("jadx");
  });

  it("reads overrides and ignores invalid numbers", () => {
    const c = compiledScanConfig({
      ENABLE_COMPILED_SCAN: "false",
      COMPILED_SCAN_MAX_ARTIFACT_MB: "10",
      COMPILED_SCAN_MAX_ARTIFACTS: "3",
      COMPILED_SCAN_MAX_FILES: "-5",
      COMPILED_SCAN_TIMEOUT_SECONDS: "abc",
      COMPILED_SCAN_SKIP_THIRD_PARTY: "0",
      COMPILED_SCAN_INCLUDE_PACKAGES: "org.apache.myproject, com/google/myteam",
      JADX_BIN: "/opt/jadx/bin/jadx",
    });
    expect(c.enabled).toBe(false);
    expect(c.maxArtifactBytes).toBe(10 * 1024 * 1024);
    expect(c.maxArtifacts).toBe(3);
    expect(c.maxFiles).toBe(5000);
    expect(c.timeoutMs).toBe(600_000);
    expect(c.skipThirdParty).toBe(false);
    expect(c.includePackages).toEqual(["org/apache/myproject", "com/google/myteam"]);
    expect(c.jadxBin).toBe("/opt/jadx/bin/jadx");
  });

  it("normalises package lists", () => {
    expect(parsePackageList(" com.acme.vendor ,, org/foo/ ,Acme.Sdk")).toEqual(["com/acme/vendor", "org/foo", "Acme/Sdk"]);
  });
});
