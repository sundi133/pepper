/**
 * Running the decompilers and trimming what they write to the source worth
 * scanning.
 *
 *   JAR / WAR / EAR / .class   Vineflower (JVM bytecode → Java)
 *   APK / AAB / DEX            jadx (Dalvik bytecode → Java, plus decoded resources)
 *   .NET DLL / EXE             ilspycmd (IL → C#)
 *
 * Each tool is a child process with a timeout that is killed, with its whole
 * process group, when the scan is stopped or cancelled.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import type { CompiledArtifact } from "./artifacts";
import type { CompiledScanConfig } from "./config";
import { isThirdPartyPackage, packagePathOf, vineflowerExcludeRegex, type PackageFilter } from "./third-party";

// ─── Process runner ───────────────────────────────────────────────────

export interface ToolRun {
  bin: string;
  args: string[];
  env?: NodeJS.ProcessEnv;
  timeoutMs: number;
  signal?: AbortSignal;
}

export interface ToolResult {
  /** Exit code; null when the process could not start or was killed. */
  code: number | null;
  timedOut: boolean;
  aborted: boolean;
  /** Last few KB of stderr. */
  stderr: string;
  /** Set when the binary could not be started (not installed). */
  spawnError?: string;
}

export type ToolRunner = (run: ToolRun) => Promise<ToolResult>;

/** Spawn a decompiler; kill its process group on timeout or abort. */
export const spawnTool: ToolRunner = (run) =>
  new Promise((resolve) => {
    if (run.signal?.aborted) {
      resolve({ code: null, timedOut: false, aborted: true, stderr: "" });
      return;
    }
    const isWin = process.platform === "win32";
    const child = spawn(run.bin, run.args, {
      env: run.env ?? process.env,
      stdio: ["ignore", "ignore", "pipe"],
      // Own process group, so the JVM / dotnet started by a wrapper script dies with it.
      detached: !isWin,
      windowsHide: true,
    });
    let stderr = "";
    let timedOut = false;
    let aborted = false;
    let settled = false;
    const kill = () => {
      try {
        if (!isWin && child.pid) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        try {
          child.kill("SIGKILL");
        } catch {
          // already gone
        }
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, run.timeoutMs);
    const onAbort = () => {
      aborted = true;
      kill();
    };
    run.signal?.addEventListener("abort", onAbort, { once: true });
    const finish = (result: ToolResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      run.signal?.removeEventListener("abort", onAbort);
      resolve(result);
    };
    child.stderr?.on("data", (d) => {
      stderr = (stderr + String(d)).slice(-4000);
    });
    child.on("error", (err) => {
      finish({ code: null, timedOut, aborted, stderr, spawnError: err.message });
    });
    child.on("close", (code) => {
      finish({ code: timedOut || aborted ? null : code, timedOut, aborted, stderr });
    });
  });

// ─── Commands ─────────────────────────────────────────────────────────

export type DecompilerName = "vineflower" | "jadx" | "ilspycmd";

export interface DecompileCommand {
  tool: DecompilerName;
  bin: string;
  args: string[];
  env: NodeJS.ProcessEnv;
}

/**
 * Command line for one artifact. `input` is the artifact (or, for loose
 * classes, a staging folder laid out by package); `outDir` must exist.
 */
export function buildDecompileCommand(opts: {
  kind: CompiledArtifact["kind"];
  input: string;
  outDir: string;
  tmpDir: string;
  config: CompiledScanConfig;
  filter: PackageFilter;
}): DecompileCommand {
  const { config } = opts;
  const javaEnv = { ...process.env, JAVA_OPTS: config.javaOpts };
  switch (opts.kind) {
    case "jvm":
    case "classes": {
      const args = ["--log-level=error", `--thread-count=${config.threads}`];
      const exclude = vineflowerExcludeRegex(opts.filter);
      if (exclude) args.push(`--excluded-classes=${exclude}`);
      // Loose classes: their resources are already in the scan as ordinary files.
      if (opts.kind === "classes") args.push("--skip-extra-files=1");
      args.push(opts.input, opts.outDir);
      return { tool: "vineflower", bin: config.vineflowerBin, args, env: javaEnv };
    }
    case "android":
      return {
        tool: "jadx",
        bin: config.jadxBin,
        args: [
          "--log-level",
          "error",
          "--comments-level",
          "warn",
          "--threads-count",
          String(config.threads),
          "-Pdex-input.verify-checksum=no",
          "--output-dir",
          opts.outDir,
          "--output-dir-src",
          opts.outDir,
          "--output-dir-res",
          opts.outDir,
          opts.input,
        ],
        env: {
          ...javaEnv,
          JADX_TMP_DIR: opts.tmpDir,
          JADX_CACHE_DIR: opts.tmpDir,
          JADX_CONFIG_DIR: opts.tmpDir,
        },
      };
    case "dotnet":
      return {
        tool: "ilspycmd",
        bin: config.ilspycmdBin,
        args: ["--project", "--nested-directories", "--disable-updatecheck", "--outputdir", opts.outDir, opts.input],
        env: {
          ...process.env,
          DOTNET_SYSTEM_GLOBALIZATION_INVARIANT: "1",
          DOTNET_CLI_TELEMETRY_OPTOUT: "1",
        },
      };
  }
}

// ─── Output trimming ──────────────────────────────────────────────────

/** Decompiled source the scanners read. */
const SOURCE_EXTENSIONS = new Set([".java", ".kt", ".cs", ".vb"]);

/** Other text worth scanning: web content shipped in a WAR, config and resources (secrets). */
const RESOURCE_EXTENSIONS = new Set([
  ".jsp",
  ".jspx",
  ".jspf",
  ".tag",
  ".tagx",
  ".xhtml",
  ".html",
  ".htm",
  ".js",
  ".mjs",
  ".vm",
  ".ftl",
  ".xml",
  ".properties",
  ".yml",
  ".yaml",
  ".json",
  ".conf",
  ".config",
  ".ini",
  ".toml",
  ".resx",
]);

/** Archives a JVM archive may carry inside it (a WAR inside an EAR). */
export const NESTED_ARCHIVE_EXTENSIONS = new Set([".jar", ".war", ".ear"]);

/**
 * Whether a file written by a decompiler is kept. `innerPath` is relative to
 * the artifact's output folder, with forward slashes.
 */
export function isRetainedOutput(innerPath: string, filter: PackageFilter): boolean {
  const ext = path.posix.extname(innerPath).toLowerCase();
  if (!SOURCE_EXTENSIONS.has(ext) && !RESOURCE_EXTENSIONS.has(ext)) return false;
  const lower = innerPath.toLowerCase();
  // Build metadata (embedded poms belong to SCA) and signatures.
  if (lower.startsWith("meta-inf/maven/") || lower.includes("/meta-inf/maven/")) return false;
  // Android resources: keep values (strings, configs) and xml (network security
  // config, file provider paths); layouts, drawables and animations are noise.
  if (lower.startsWith("res/") && !/^res\/(values[^/]*|xml|raw)\//.test(lower)) return false;
  // Libraries bundled into the artifact.
  if (isThirdPartyPackage(packagePathOf(innerPath), filter)) return false;
  return true;
}

export function isSourceOutput(innerPath: string): boolean {
  return SOURCE_EXTENSIONS.has(path.posix.extname(innerPath).toLowerCase());
}

export interface OutputFile {
  /** Path inside the artifact's output folder. */
  innerPath: string;
  bytes: number;
}

/** Every regular file under `dir`, relative, with forward slashes. Symlinks are ignored. */
export function walkFiles(dir: string): OutputFile[] {
  const out: OutputFile[] = [];
  const walk = (abs: string, prefix: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const rel = prefix ? `${prefix}/${e.name}` : e.name;
      const full = path.join(abs, e.name);
      if (e.isDirectory()) walk(full, rel);
      else if (e.isFile()) {
        let bytes = 0;
        try {
          bytes = fs.statSync(full).size;
        } catch {
          continue;
        }
        out.push({ innerPath: rel, bytes });
      }
    }
  };
  walk(dir, "");
  return out;
}

export interface Budget {
  files: number;
  bytes: number;
}

export interface TrimResult {
  kept: OutputFile[];
  /** Files dropped as third-party, binary or not worth scanning. */
  dropped: number;
  /** Files dropped because the per-scan output budget ran out. */
  overBudget: number;
  /** Files dropped for being larger than the per-file limit. */
  tooLarge: number;
}

/**
 * Decide which output files stay: retained kinds only, then source before
 * resources, within the remaining budget (which is reduced in place).
 * Everything else is deleted from disk, so a scanner that walks the whole
 * work dir (OpenGrep) never sees it.
 */
export function trimOutput(outDir: string, filter: PackageFilter, budget: Budget, maxFileBytes: number): TrimResult {
  const files = walkFiles(outDir);
  const retained: OutputFile[] = [];
  const remove: OutputFile[] = [];
  let tooLarge = 0;
  for (const f of files) {
    if (!isRetainedOutput(f.innerPath, filter)) remove.push(f);
    else if (f.bytes > maxFileBytes) {
      tooLarge++;
      remove.push(f);
    } else retained.push(f);
  }
  const dropped = remove.length - tooLarge;
  retained.sort((a, b) => {
    const sa = isSourceOutput(a.innerPath) ? 0 : 1;
    const sb = isSourceOutput(b.innerPath) ? 0 : 1;
    return sa !== sb ? sa - sb : a.innerPath.localeCompare(b.innerPath);
  });
  const kept: OutputFile[] = [];
  let overBudget = 0;
  for (const f of retained) {
    if (budget.files > 0 && budget.bytes >= f.bytes) {
      kept.push(f);
      budget.files--;
      budget.bytes -= f.bytes;
    } else {
      overBudget++;
      remove.push(f);
    }
  }
  for (const f of remove) {
    try {
      fs.rmSync(path.join(outDir, f.innerPath), { force: true });
    } catch {
      // best effort; the work dir is removed after the scan
    }
  }
  removeEmptyDirs(outDir);
  return { kept, dropped, overBudget, tooLarge };
}

function removeEmptyDirs(dir: string): boolean {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return false;
  }
  let empty = true;
  for (const e of entries) {
    if (e.isDirectory() && removeEmptyDirs(path.join(dir, e.name))) {
      try {
        fs.rmdirSync(path.join(dir, e.name));
        continue;
      } catch {
        // keep it
      }
    }
    empty = false;
  }
  return empty;
}

/**
 * Lay loose class files out by package under `stagingDir`
 * (com/example/Login.class) so the decompiler writes com/example/Login.java.
 */
export function stageClasses(
  workDir: string,
  classes: NonNullable<CompiledArtifact["classes"]>,
  stagingDir: string,
): number {
  let staged = 0;
  for (const c of classes) {
    const target = path.join(stagingDir, ...`${c.className}.class`.split("/"));
    // Class names come from the file: never let one escape the staging folder.
    if (!target.startsWith(stagingDir + path.sep)) continue;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.copyFileSync(path.join(workDir, c.path), target);
    staged++;
  }
  return staged;
}

/** A short, single-line excerpt of a tool's stderr for scan notes. */
export function stderrExcerpt(stderr: string, max = 300): string {
  const lines = stderr
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  const text = lines.slice(-3).join(" | ");
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}
