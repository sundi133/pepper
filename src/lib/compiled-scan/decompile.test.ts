import { describe, expect, it } from "vitest";
import { compiledScanConfig } from "./config";
import { buildDecompileCommand, isRetainedOutput, spawnTool, stderrExcerpt } from "./decompile";

const filter = { skipThirdParty: true, excludePackages: [], includePackages: [] };
const config = compiledScanConfig({});

describe("buildDecompileCommand", () => {
  const base = { input: "/w/app", outDir: "/w/__decompiled__/1-app", tmpDir: "/w/.tmp/1", config, filter };

  it("uses Vineflower for JVM archives and loose classes", () => {
    const jar = buildDecompileCommand({ ...base, kind: "jvm" });
    expect(jar.tool).toBe("vineflower");
    expect(jar.args.slice(-2)).toEqual(["/w/app", "/w/__decompiled__/1-app"]);
    expect(jar.args).toContain("--log-level=error");
    expect(jar.args).not.toContain("--skip-extra-files=1");
    const classes = buildDecompileCommand({ ...base, kind: "classes" });
    expect(classes.args).toContain("--skip-extra-files=1");
    expect(buildDecompileCommand({ ...base, kind: "jvm", filter: { ...filter, skipThirdParty: false } }).args.some((a) =>
      a.startsWith("--excluded-classes"),
    )).toBe(false);
  });

  it("uses jadx for Android, writing sources and resources to one folder with a private temp dir", () => {
    const cmd = buildDecompileCommand({ ...base, kind: "android" });
    expect(cmd.tool).toBe("jadx");
    for (const flag of ["--output-dir", "--output-dir-src", "--output-dir-res"]) {
      expect(cmd.args[cmd.args.indexOf(flag) + 1]).toBe(base.outDir);
    }
    expect(cmd.args.at(-1)).toBe("/w/app");
    expect(cmd.env.JADX_TMP_DIR).toBe(base.tmpDir);
    expect(cmd.env.JADX_CACHE_DIR).toBe(base.tmpDir);
  });

  it("uses ilspycmd for .NET with no update check (works offline)", () => {
    const cmd = buildDecompileCommand({ ...base, kind: "dotnet" });
    expect(cmd.tool).toBe("ilspycmd");
    expect(cmd.args).toEqual([
      "--project",
      "--nested-directories",
      "--disable-updatecheck",
      "--outputdir",
      base.outDir,
      "/w/app",
    ]);
    expect(cmd.env.DOTNET_SYSTEM_GLOBALIZATION_INVARIANT).toBe("1");
  });
});

describe("isRetainedOutput", () => {
  it("keeps source, web content and config; drops binaries, build metadata and noise", () => {
    const keep = [
      "com/example/Login.java",
      "MyApp/Login.cs",
      "WEB-INF/web.xml",
      "index.jsp",
      "application.properties",
      "AndroidManifest.xml",
      "res/values/strings.xml",
      "res/values-fr/strings.xml",
      "res/xml/network_security_config.xml",
      "assets/config.json",
    ];
    const drop = [
      "com/example/Login.class",
      "WEB-INF/lib/dep.jar",
      "META-INF/MANIFEST.MF",
      "META-INF/CERT.RSA",
      "META-INF/maven/com.acme/app/pom.xml",
      "res/layout/main.xml",
      "res/drawable/icon.png",
      "MyApp.csproj",
      "androidx/core/Compat.java",
      "org/apache/commons/Lang.java",
    ];
    for (const p of keep) expect(isRetainedOutput(p, filter), p).toBe(true);
    for (const p of drop) expect(isRetainedOutput(p, filter), p).toBe(false);
  });
});

describe("spawnTool", () => {
  const node = process.execPath;

  it("reports the exit code and stderr", async () => {
    const r = await spawnTool({ bin: node, args: ["-e", "console.error('boom'); process.exit(3)"], timeoutMs: 10_000 });
    expect(r.code).toBe(3);
    expect(r.stderr).toContain("boom");
    expect(r.timedOut).toBe(false);
  });

  it("kills a process that runs past its timeout", async () => {
    const started = Date.now();
    const r = await spawnTool({ bin: node, args: ["-e", "setTimeout(() => {}, 60000)"], timeoutMs: 300 });
    expect(r.timedOut).toBe(true);
    expect(r.code).toBeNull();
    expect(Date.now() - started).toBeLessThan(10_000);
  });

  it("kills the process when the scan is stopped", async () => {
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 100);
    const r = await spawnTool({ bin: node, args: ["-e", "setTimeout(() => {}, 60000)"], timeoutMs: 60_000, signal: ac.signal });
    expect(r.aborted).toBe(true);
    expect(r.code).toBeNull();
  });

  it("does not start when already aborted", async () => {
    const ac = new AbortController();
    ac.abort();
    const r = await spawnTool({ bin: node, args: ["-e", ""], timeoutMs: 1000, signal: ac.signal });
    expect(r.aborted).toBe(true);
  });

  it("reports a missing binary instead of throwing", async () => {
    const r = await spawnTool({ bin: "pepper-no-such-decompiler", args: [], timeoutMs: 1000 });
    expect(r.spawnError).toMatch(/ENOENT/);
  });

  it("shortens stderr for notes", () => {
    expect(stderrExcerpt("a\n\nb\nc\nd\n")).toBe("b | c | d");
    expect(stderrExcerpt("x".repeat(500)).length).toBe(300);
  });
});
