import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { compiledScanConfig } from "./config";
import type { ToolResult, ToolRun, ToolRunner } from "./decompile";
import { DECOMPILED_DIR, runCompiledScan } from "./index";
import { classFile, dexFile, peFile, zipFile } from "./test-fixtures";

const silentLog = { info: vi.fn(), warn: vi.fn() } as never;

let workDir: string;
beforeEach(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-compiled-"));
});
afterEach(() => {
  fs.rmSync(workDir, { recursive: true, force: true });
});

function put(rel: string, content: Buffer | string, root = workDir) {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

const ok: ToolResult = { code: 0, timedOut: false, aborted: false, stderr: "" };

/** Stand-in for the real decompilers: writes plausible output for each input. */
function fakeRunner(overrides: (run: ToolRun, out: string) => ToolResult | null = () => null) {
  const calls: ToolRun[] = [];
  const runner: ToolRunner = async (run) => {
    calls.push(run);
    const tool = path.basename(run.bin);
    const out =
      tool === "jadx"
        ? run.args[run.args.indexOf("--output-dir") + 1]
        : tool === "ilspycmd"
          ? run.args[run.args.indexOf("--outputdir") + 1]
          : run.args[run.args.length - 1];
    const input = tool === "vineflower" ? run.args[run.args.length - 2] : run.args[run.args.length - 1];
    const custom = overrides(run, out);
    if (custom) return custom;
    const name = path.basename(input);
    if (tool === "jadx") {
      put("com/example/Main.java", "class Main { String k = \"AKIA\"; }", out);
      put("androidx/core/Compat.java", "class Compat {}", out);
      put("AndroidManifest.xml", "<manifest/>", out);
      put("res/values/strings.xml", "<resources/>", out);
      put("res/layout/main.xml", "<LinearLayout/>", out);
      put("res/drawable/icon.png", Buffer.alloc(10), out);
      put("META-INF/CERT.RSA", Buffer.alloc(10), out);
    } else if (tool === "ilspycmd") {
      put("MyApp/Services/Login.cs", "class Login {}", out);
      put("MyApp.csproj", "<Project/>", out);
    } else if (name === "app.ear") {
      put("META-INF/application.xml", "<application/>", out);
      put("web.war", zipFile({ "x.class": "x" }), out);
      put("lib/dep.jar", zipFile({ "y.class": "y" }), out);
    } else if (name.endsWith(".war")) {
      put("WEB-INF/classes/com/x/A.java", "class A {}", out);
      put("WEB-INF/lib/spring.jar", zipFile({}), out);
      put("index.jsp", "<%= request.getParameter(\"q\") %>", out);
    } else if (name === "classes") {
      // Loose classes are staged by package for the decompiler.
      expect(fs.existsSync(path.join(input, "com", "acme", "Login.class"))).toBe(true);
      put("com/acme/Login.java", "class Login {}", out);
    } else {
      put("com/example/Login.java", "class Login {}", out);
      put("org/apache/commons/Lang.java", "class Lang {}", out);
      put("META-INF/MANIFEST.MF", "Manifest-Version: 1.0", out);
      put("application.properties", "db.password=x", out);
    }
    return ok;
  };
  return { runner, calls };
}

function config(env: Record<string, string> = {}) {
  return compiledScanConfig(env);
}

describe("runCompiledScan", () => {
  it("decompiles each artifact kind and maps its files back to the artifact", async () => {
    put("dist/app.jar", zipFile({ "com/example/Login.class": classFile("com/example/Login") }));
    put("app.ear", zipFile({ "web.war": "w" }));
    put("mobile/app.apk", zipFile({ "classes.dex": dexFile() }));
    put("publish/MyApp.dll", peFile({ clr: true }));
    put("publish/native.dll", peFile({ clr: false }));
    put("publish/Newtonsoft.Json.dll", peFile({ clr: true }));
    put("WEB-INF/lib/dep.jar", zipFile({}));
    put("out/classes/com/acme/Login.class", classFile("com/acme/Login"));
    put("README.md", "# readme");

    const progress: string[] = [];
    const { runner, calls } = fakeRunner();
    const outcome = await runCompiledScan({
      workDir,
      fileList: ["README.md"],
      scanType: "FULL",
      config: config(),
      runner,
      log: silentLog,
      onProgress: (m) => progress.push(m),
    });

    const display = outcome.files.map((f) => outcome.pathMap.resolve(f)!.displayPath).sort();
    expect(display).toEqual([
      "app.ear!/META-INF/application.xml",
      "app.ear!/web.war!/WEB-INF/classes/com/x/A.java",
      "app.ear!/web.war!/index.jsp",
      "dist/app.jar!/application.properties",
      "dist/app.jar!/com/example/Login.java",
      "mobile/app.apk!/AndroidManifest.xml",
      "mobile/app.apk!/com/example/Main.java",
      "mobile/app.apk!/res/values/strings.xml",
      "out/classes!/com/acme/Login.java",
      "publish/MyApp.dll!/MyApp/Services/Login.cs",
    ]);
    // Every returned file exists; everything trimmed away is gone from disk.
    for (const f of outcome.files) expect(fs.existsSync(path.join(workDir, f)), f).toBe(true);
    const onDisk: string[] = [];
    const walk = (d: string) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) walk(p);
        else onDisk.push(path.relative(workDir, p).split(path.sep).join("/"));
      }
    };
    walk(path.join(workDir, DECOMPILED_DIR));
    expect(onDisk.sort()).toEqual([...outcome.files].sort());
    expect(fs.existsSync(path.join(workDir, ".pepper-decompile-tmp"))).toBe(false);

    // Tool per kind; the nested WAR ran as its own artifact.
    expect(calls.map((c) => c.bin)).toEqual(["vineflower", "vineflower", "jadx", "ilspycmd", "vineflower", "vineflower"]);
    const vf = calls.find((c) => c.bin === "vineflower")!;
    expect(vf.args.some((a) => a.startsWith("--excluded-classes="))).toBe(true);
    expect(vf.env?.JAVA_OPTS).toContain("MaxRAMPercentage");
    // Vineflower writes an archive, not a folder, to a destination named like one.
    for (const c of calls.filter((x) => x.bin === "vineflower")) {
      expect(c.args.at(-1)).not.toMatch(/\.(jar|war|ear|zip)$/i);
    }

    const s = outcome.summary;
    expect(s.decompiled).toBe(6);
    expect(s.failed).toBe(0);
    expect(s.filesAdded).toBe(10);
    expect(s.skipped).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ path: "publish/native.dll", reason: "native" }),
        expect.objectContaining({ path: "publish/Newtonsoft.Json.dll", reason: "third-party" }),
        expect.objectContaining({ path: "WEB-INF/lib/dep.jar", reason: "dependency" }),
        expect.objectContaining({ path: "app.ear!/lib/dep.jar", reason: "dependency" }),
        expect.objectContaining({ path: "app.ear!/web.war!/WEB-INF/lib/spring.jar", reason: "dependency" }),
      ]),
    );
    // Notes worth reading come before routine dependency skips.
    expect(s.skipped[0].reason).not.toBe("dependency");
    expect(progress[0]).toBe("Decompiling 5 compiled artifacts…");
    expect(progress).toContain("Decompiling mobile/app.apk (3/6) with jadx");
    expect(progress.at(-1)).toMatch(/^Compiled code: 6 artifacts decompiled, 10 files added to the scan; 5 skipped$/);
  });

  it("does nothing, and creates nothing, for a scan without compiled artifacts", async () => {
    put("src/index.ts", "export {}");
    const { runner, calls } = fakeRunner();
    const outcome = await runCompiledScan({ workDir, fileList: ["src/index.ts"], scanType: "FULL", config: config(), runner, log: silentLog });
    expect(outcome.files).toEqual([]);
    expect(outcome.pathMap.size).toBe(0);
    expect(calls).toEqual([]);
    expect(fs.readdirSync(workDir)).toEqual(["src"]);
  });

  it("is off when ENABLE_COMPILED_SCAN=false", async () => {
    put("app.jar", zipFile({}));
    const { runner, calls } = fakeRunner();
    const outcome = await runCompiledScan({
      workDir,
      fileList: [],
      scanType: "FULL",
      config: config({ ENABLE_COMPILED_SCAN: "false" }),
      runner,
      log: silentLog,
    });
    expect(outcome.files).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("records native binaries without running anything", async () => {
    put("Setup.exe", peFile({ clr: false }));
    const { runner, calls } = fakeRunner();
    const outcome = await runCompiledScan({ workDir, fileList: ["Setup.exe"], scanType: "FULL", config: config(), runner, log: silentLog });
    expect(calls).toEqual([]);
    expect(outcome.summary.skipped).toEqual([expect.objectContaining({ path: "Setup.exe", reason: "native" })]);
    expect(fs.existsSync(path.join(workDir, DECOMPILED_DIR))).toBe(false);
  });

  it("stops adding files at the per-scan file limit and notes it", async () => {
    put("a.jar", zipFile({}));
    put("b.jar", zipFile({}));
    const { runner } = fakeRunner();
    const outcome = await runCompiledScan({
      workDir,
      fileList: [],
      scanType: "FULL",
      config: config({ COMPILED_SCAN_MAX_FILES: "1" }),
      runner,
      log: silentLog,
    });
    // Source first: the one file kept is a.jar's Java class, not its properties.
    expect(outcome.files.map((f) => outcome.pathMap.resolve(f)!.displayPath)).toEqual(["a.jar!/com/example/Login.java"]);
    expect(outcome.summary.truncated).toBe(true);
    expect(outcome.summary.artifacts[0].note).toMatch(/over the output limit/);
    expect(outcome.summary.skipped).toEqual([expect.objectContaining({ path: "b.jar", reason: "output-limit" })]);
  });

  it("enforces the byte limit and drops oversized files", async () => {
    put("a.jar", zipFile({}));
    const { runner } = fakeRunner((run, out) => {
      put("com/x/Huge.java", "x".repeat(2 * 1024 * 1024), out);
      put("com/x/Small.java", "class Small {}", out);
      return ok;
    });
    const outcome = await runCompiledScan({ workDir, fileList: [], scanType: "FULL", config: config(), runner, log: silentLog });
    expect(outcome.files).toHaveLength(1);
    expect(outcome.files[0]).toMatch(/Small\.java$/);
  });

  it("reports a timed-out artifact, keeping partial output when there is some", async () => {
    put("a.jar", zipFile({}));
    put("b.jar", zipFile({}));
    const { runner } = fakeRunner((run, out) => {
      if (run.args.at(-2)!.endsWith("a.jar")) {
        put("com/x/A.java", "class A {}", out);
      }
      return { code: null, timedOut: true, aborted: false, stderr: "" };
    });
    const outcome = await runCompiledScan({
      workDir,
      fileList: [],
      scanType: "FULL",
      config: config({ COMPILED_SCAN_TIMEOUT_SECONDS: "5" }),
      runner,
      log: silentLog,
    });
    expect(outcome.summary.artifacts).toEqual([
      expect.objectContaining({ artifact: "a.jar", status: "partial", note: "timed out; partial output kept" }),
    ]);
    expect(outcome.summary.skipped).toEqual([
      expect.objectContaining({ path: "b.jar", reason: "timeout", detail: "vineflower did not finish within 5s" }),
    ]);
    expect(outcome.summary.failed).toBe(1);
  });

  it("passes the per-artifact timeout to the runner", async () => {
    put("a.jar", zipFile({}));
    const { runner, calls } = fakeRunner();
    await runCompiledScan({ workDir, fileList: [], scanType: "FULL", config: config({ COMPILED_SCAN_TIMEOUT_SECONDS: "7" }), runner, log: silentLog });
    expect(calls[0].timeoutMs).toBe(7000);
  });

  it("reports a failed decompile with the tool's error", async () => {
    put("a.jar", zipFile({}));
    const { runner } = fakeRunner(() => ({ code: 1, timedOut: false, aborted: false, stderr: "line1\njava.lang.OutOfMemoryError: Java heap space\n" }));
    const outcome = await runCompiledScan({ workDir, fileList: [], scanType: "FULL", config: config(), runner, log: silentLog });
    expect(outcome.files).toEqual([]);
    expect(outcome.summary.skipped).toEqual([
      expect.objectContaining({ path: "a.jar", reason: "failed", detail: expect.stringContaining("OutOfMemoryError") }),
    ]);
  });

  it("skips artifacts whose decompiler is not installed, trying the tool only once", async () => {
    put("a.jar", zipFile({}));
    put("b.jar", zipFile({}));
    put("App.dll", peFile({ clr: true }));
    const { runner, calls } = fakeRunner((run) =>
      run.bin === "vineflower" ? { code: null, timedOut: false, aborted: false, stderr: "", spawnError: "spawn vineflower ENOENT" } : null,
    );
    const outcome = await runCompiledScan({ workDir, fileList: [], scanType: "FULL", config: config(), runner, log: silentLog });
    expect(calls.map((c) => c.bin)).toEqual(["vineflower", "ilspycmd"]);
    expect(outcome.summary.skipped.filter((s) => s.reason === "tool-missing").map((s) => s.path)).toEqual(["a.jar", "b.jar"]);
    expect(outcome.summary.decompiled).toBe(1);
  });

  it("stops at once when the scan is stopped or cancelled", async () => {
    put("a.jar", zipFile({}));
    put("b.jar", zipFile({}));
    const ac = new AbortController();
    const { runner, calls } = fakeRunner(() => {
      ac.abort();
      return { code: null, timedOut: false, aborted: true, stderr: "" };
    });
    const outcome = await runCompiledScan({
      workDir,
      fileList: [],
      scanType: "FULL",
      config: config(),
      runner,
      signal: ac.signal,
      log: silentLog,
    });
    expect(calls).toHaveLength(1);
    expect(outcome.files).toEqual([]);
    expect(fs.existsSync(path.join(workDir, ".pepper-decompile-tmp"))).toBe(false);
  });

  it("uses a different output folder when the source already has __decompiled__", async () => {
    put("__decompiled__/notes.txt", "mine");
    put("a.jar", zipFile({}));
    const { runner } = fakeRunner();
    const outcome = await runCompiledScan({ workDir, fileList: [], scanType: "FULL", config: config(), runner, log: silentLog });
    expect(outcome.files.every((f) => f.startsWith("__decompiled__pepper/"))).toBe(true);
    expect(fs.readFileSync(path.join(workDir, "__decompiled__/notes.txt"), "utf8")).toBe("mine");
  });
});
