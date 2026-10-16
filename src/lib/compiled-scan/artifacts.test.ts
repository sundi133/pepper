import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { discoverArtifacts, listCompiledCandidates, type DiscoveryOptions } from "./artifacts";
import { classFile, dexFile, peFile, zipFile } from "./test-fixtures";

let workDir: string;
beforeEach(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-artifacts-"));
});
afterEach(() => {
  fs.rmSync(workDir, { recursive: true, force: true });
});

function put(rel: string, content: Buffer | string) {
  const abs = path.join(workDir, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

const jar = () => zipFile({ "com/example/App.class": classFile("com/example/App") });
const filter = { skipThirdParty: true, excludePackages: [], includePackages: [] };

function discover(overrides: Partial<DiscoveryOptions> = {}) {
  const candidates = listCompiledCandidates({ workDir, fileList: [], scanType: "FULL", skipThirdParty: true });
  return discoverArtifacts({
    workDir,
    candidates,
    sourceFiles: [],
    maxArtifactBytes: 50 * 1024 * 1024,
    maxArtifacts: 25,
    filter,
    ...overrides,
  });
}

describe("listCompiledCandidates", () => {
  it("finds artifacts anywhere, including build-output folders, but not in VCS or node_modules", () => {
    put("app.apk", zipFile({ "classes.dex": dexFile() }));
    put("target/service.war", jar());
    put("build/outputs/apk/release/app-release.apk", jar());
    put("node_modules/pkg/tool.jar", jar());
    put(".git/objects/x.jar", jar());
    put("src/Main.java", "class Main {}");
    const found = listCompiledCandidates({ workDir, fileList: [], scanType: "FULL", skipThirdParty: true }).sort();
    expect(found).toEqual(["app.apk", "build/outputs/apk/release/app-release.apk", "target/service.war"]);
  });

  it("walks node_modules when third-party skipping is turned off", () => {
    put("node_modules/pkg/tool.jar", jar());
    expect(listCompiledCandidates({ workDir, fileList: [], scanType: "FULL", skipThirdParty: false })).toEqual([
      "node_modules/pkg/tool.jar",
    ]);
  });

  it("only considers changed files on a PR scan", () => {
    put("a.jar", jar());
    put("b.jar", jar());
    expect(
      listCompiledCandidates({ workDir, fileList: ["b.jar", "src/x.ts"], scanType: "INCREMENTAL", skipThirdParty: true }),
    ).toEqual(["b.jar"]);
  });
});

describe("discoverArtifacts", () => {
  it("classifies JVM, Android and .NET artifacts", () => {
    put("app.jar", jar());
    put("web.war", jar());
    put("app.ear", jar());
    put("mobile.apk", jar());
    put("bundle.aab", jar());
    put("classes.dex", dexFile());
    put("bin/App.dll", peFile({ clr: true }));
    put("tools/Setup.exe", peFile({ clr: true, pe32Plus: true }));
    const { artifacts, skipped } = discover();
    expect(skipped).toEqual([]);
    expect(Object.fromEntries(artifacts.map((a) => [a.path, a.kind]))).toEqual({
      "app.jar": "jvm",
      "web.war": "jvm",
      "app.ear": "jvm",
      "mobile.apk": "android",
      "bundle.aab": "android",
      "classes.dex": "android",
      "bin/App.dll": "dotnet",
      "tools/Setup.exe": "dotnet",
    });
  });

  it("skips native DLL/EXE with a note instead of failing", () => {
    put("bin/native.dll", peFile({ clr: false }));
    put("bin/launcher.exe", peFile({ clr: false, pe32Plus: true }));
    put("bin/readme.exe", "not a binary");
    const { artifacts, skipped } = discover();
    expect(artifacts).toEqual([]);
    expect(skipped).toEqual([
      expect.objectContaining({ path: "bin/launcher.exe", reason: "native" }),
      expect.objectContaining({ path: "bin/native.dll", reason: "native" }),
      expect.objectContaining({ path: "bin/readme.exe", reason: "unrecognized" }),
    ]);
    expect(skipped[0].detail).toMatch(/cannot be decompiled/);
  });

  it("skips artifacts in dependency folders by default", () => {
    put("WEB-INF/lib/spring-core.jar", jar());
    put("lib/commons.jar", jar());
    put("libs/okhttp.jar", jar());
    put("packages/Newtonsoft.Json/lib/net45/Foo.dll", peFile({ clr: true }));
    put("vendor/x.jar", jar());
    put(".m2/repository/a.jar", jar());
    put("app/myservice.jar", jar());
    const { artifacts, skipped } = discover();
    expect(artifacts.map((a) => a.path)).toEqual(["app/myservice.jar"]);
    expect(skipped.every((s) => s.reason === "dependency")).toBe(true);
    expect(skipped).toHaveLength(6);
  });

  it("decompiles dependency folders too when third-party skipping is off", () => {
    put("lib/commons.jar", jar());
    const { artifacts } = discover({ filter: { ...filter, skipThirdParty: false } });
    expect(artifacts.map((a) => a.path)).toEqual(["lib/commons.jar"]);
  });

  it("skips well-known library assemblies but not the application's", () => {
    put("publish/MyCompany.Api.dll", peFile({ clr: true }));
    put("publish/Newtonsoft.Json.dll", peFile({ clr: true }));
    put("publish/Microsoft.Extensions.Logging.dll", peFile({ clr: true }));
    put("publish/System.Text.Json.dll", peFile({ clr: true }));
    const { artifacts, skipped } = discover();
    expect(artifacts.map((a) => a.path)).toEqual(["publish/MyCompany.Api.dll"]);
    expect(skipped.map((s) => s.reason)).toEqual(["third-party", "third-party", "third-party"]);
  });

  it("include/exclude overrides for assemblies", () => {
    put("publish/Newtonsoft.Json.dll", peFile({ clr: true }));
    put("publish/Acme.Vendor.Sdk.dll", peFile({ clr: true }));
    const { artifacts } = discover({
      filter: { skipThirdParty: true, includePackages: ["Newtonsoft"], excludePackages: ["Acme/Vendor"] },
    });
    expect(artifacts.map((a) => a.path)).toEqual(["publish/Newtonsoft.Json.dll"]);
  });

  it("skips build output when the scan already has that language's source", () => {
    put("target/app.jar", jar());
    put("bin/Release/App.dll", peFile({ clr: true }));
    put("tools/legacy.jar", jar());
    const withJava = discover({ sourceFiles: ["src/main/java/com/x/A.java"] });
    expect(withJava.artifacts.map((a) => a.path)).toEqual(["tools/legacy.jar", "bin/Release/App.dll"]);
    expect(withJava.skipped).toEqual([expect.objectContaining({ path: "target/app.jar", reason: "build-output" })]);

    // An upload of release binaries only: build output is all there is.
    const binariesOnly = discover({ sourceFiles: ["README.md"] });
    expect(binariesOnly.artifacts.map((a) => a.path).sort()).toEqual(["bin/Release/App.dll", "target/app.jar", "tools/legacy.jar"]);
  });

  it("rejects files with a compiled extension that are not that format", () => {
    put("fake.jar", "plain text");
    put("fake.dex", "plain text");
    put("broken.apk", Buffer.concat([Buffer.from("PK\u0003\u0004"), Buffer.alloc(40)]));
    const { artifacts, skipped } = discover();
    expect(artifacts).toEqual([]);
    expect(skipped.map((s) => [s.path, s.reason, s.detail])).toEqual([
      ["broken.apk", "unrecognized", "not a readable ZIP archive"],
      ["fake.dex", "unrecognized", "not a DEX file"],
      ["fake.jar", "unrecognized", "not a ZIP-based archive"],
    ]);
  });

  it("enforces the artifact size limit, and the unpacked size of archives", () => {
    put("big.jar", Buffer.concat([jar(), Buffer.alloc(2048)]));
    put("small.jar", jar());
    const { artifacts, skipped } = discover({ maxArtifactBytes: 1024 });
    expect(artifacts.map((a) => a.path)).toEqual(["small.jar"]);
    expect(skipped).toEqual([expect.objectContaining({ path: "big.jar", reason: "too-large" })]);

    // Small on disk, but its central directory claims 5 GB unpacked.
    const bomb = zipFile({ "a.txt": "x" });
    const central = bomb.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    bomb.writeUInt32LE(0xfffffff0, central + 24);
    put("bomb.jar", bomb);
    const result = discover({ maxArtifactBytes: 1024 });
    expect(result.skipped).toContainEqual(
      expect.objectContaining({ path: "bomb.jar", reason: "too-large", detail: expect.stringMatching(/^unpacks to/) }),
    );
  });

  it("caps the number of artifacts per scan, shallow paths first", () => {
    put("z/deep/one.jar", jar());
    put("a.jar", jar());
    put("b.jar", jar());
    const { artifacts, skipped } = discover({ maxArtifacts: 2 });
    expect(artifacts.map((a) => a.path)).toEqual(["a.jar", "b.jar"]);
    expect(skipped).toEqual([expect.objectContaining({ path: "z/deep/one.jar", reason: "artifact-limit" })]);
  });

  it("groups loose class files by class root and skips classes whose source is in the scan", () => {
    put("webapp/WEB-INF/classes/com/acme/Login.class", classFile("com/acme/Login"));
    put("webapp/WEB-INF/classes/com/acme/Login$1.class", classFile("com/acme/Login$1"));
    put("webapp/WEB-INF/classes/com/acme/Util.class", classFile("com/acme/Util"));
    put("Standalone.class", classFile("Standalone"));
    put("misplaced/Thing.class", classFile("org/other/Thing"));
    put("bad.class", "nope");
    const { artifacts, skipped } = discover({ sourceFiles: ["src/com/acme/Util.java"] });
    const groups = Object.fromEntries(artifacts.map((a) => [a.path, a.classes?.map((c) => c.className).sort()]));
    expect(groups).toEqual({
      "": ["Standalone"],
      misplaced: ["org/other/Thing"],
      "webapp/WEB-INF/classes": ["com/acme/Login", "com/acme/Login$1"],
    });
    expect(artifacts.every((a) => a.kind === "classes")).toBe(true);
    expect(skipped).toEqual([
      expect.objectContaining({ path: "bad.class", reason: "unrecognized" }),
      expect.objectContaining({ path: "webapp/WEB-INF/classes/com/acme/Util.class", reason: "source-present" }),
    ]);
  });
});
