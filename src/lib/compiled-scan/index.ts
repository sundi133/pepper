/**
 * Compiled-code scan: turn the compiled artifacts in a scan (JAR / WAR / EAR /
 * .class, APK / AAB / DEX, .NET DLL / EXE) back into source so the existing
 * source scanners (AI SAST, OpenGrep, secrets) can review it.
 *
 * Runs in the worker after the source is checked out and before the scanners.
 * Each artifact is decompiled into its own folder under `__decompiled__/` in
 * the work dir (removed with it); the files kept there are returned for the
 * scanners, and a path map rewrites findings in them to
 * `<artifact>!/<file inside it>` (see path-mapping.ts, finding-origin.ts).
 *
 * Skipped, with a note in the scan: artifacts in dependency folders, build
 * output of source already in the scan, well-known third-party libraries,
 * native (non-.NET) DLL/EXE, and anything over the configured limits.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { logger } from "@/lib/logger";
import {
  artifactLabel,
  discoverArtifacts,
  listCompiledCandidates,
  type CompiledArtifact,
  type SkipNote,
  type SkipReason,
} from "./artifacts";
import { compiledScanConfig, type CompiledScanConfig } from "./config";
import {
  buildDecompileCommand,
  NESTED_ARCHIVE_EXTENSIONS,
  spawnTool,
  stageClasses,
  stderrExcerpt,
  trimOutput,
  walkFiles,
  type Budget,
  type DecompilerName,
  type ToolRunner,
} from "./decompile";
import { DecompiledPathMap, type DecompiledArtifactRecord } from "./path-mapping";
import { isInDependencyDir, type PackageFilter } from "./third-party";

export { compiledScanConfig } from "./config";
export { DecompiledPathMap } from "./path-mapping";

/** Folder (in the work dir) that holds decompiled source. */
export const DECOMPILED_DIR = "__decompiled__";
const TMP_DIR = ".pepper-decompile-tmp";
/** Nested archives (a WAR inside an EAR) are followed this many levels deep. */
const MAX_NESTING = 2;
/** Skip notes kept in the scan record; the counts cover the rest. */
const MAX_NOTES = 50;

export interface DecompiledArtifactSummary {
  artifact: string;
  tool: DecompilerName;
  files: number;
  status: "ok" | "partial";
  note?: string;
}

export interface CompiledScanSummary {
  decompiled: number;
  failed: number;
  filesAdded: number;
  bytesAdded: number;
  /** Some decompiled output was dropped because a per-scan limit was reached. */
  truncated: boolean;
  artifacts: DecompiledArtifactSummary[];
  skipped: SkipNote[];
  skippedByReason: Partial<Record<SkipReason, number>>;
}

export interface CompiledScanOutcome {
  /** Work-dir-relative decompiled files, for the source scanners. */
  files: string[];
  pathMap: DecompiledPathMap;
  summary: CompiledScanSummary;
}

interface QueueItem {
  artifact: CompiledArtifact;
  /** Display name in findings and notes. */
  label: string;
  /** Absolute path the decompiler reads (a staged copy for nested archives). */
  input: string;
  depth: number;
}

type Log = Pick<typeof logger, "info" | "warn">;

const pluralize = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/**
 * Output folder name for an artifact. No dots: Vineflower treats a destination
 * ending in .jar/.zip as an archive to write, not a folder.
 */
function safeName(name: string): string {
  const s = name.replace(/[^A-Za-z0-9_-]/g, "_");
  return (s || "artifact").slice(0, 80);
}

export function emptyOutcome(skipped: SkipNote[] = []): CompiledScanOutcome {
  return { files: [], pathMap: new DecompiledPathMap(), summary: summarize([], skipped, 0, 0, 0, false) };
}

function summarize(
  artifacts: DecompiledArtifactSummary[],
  skipped: SkipNote[],
  failed: number,
  files: number,
  bytes: number,
  truncated: boolean,
): CompiledScanSummary {
  const skippedByReason: Partial<Record<SkipReason, number>> = {};
  for (const s of skipped) skippedByReason[s.reason] = (skippedByReason[s.reason] ?? 0) + 1;
  // Notes for things worth a person's attention first; dependency skips are expected.
  const ordered = [...skipped].sort((a, b) => Number(a.reason === "dependency") - Number(b.reason === "dependency"));
  return {
    decompiled: artifacts.length,
    failed,
    filesAdded: files,
    bytesAdded: bytes,
    truncated,
    artifacts,
    skipped: ordered.slice(0, MAX_NOTES),
    skippedByReason,
  };
}

/** One line for logs and the scan's progress feed. */
export function describeOutcome(summary: CompiledScanSummary): string {
  const parts = [
    `Compiled code: ${pluralize(summary.decompiled, "artifact")} decompiled, ${pluralize(summary.filesAdded, "file")} added to the scan`,
  ];
  const skippedCount = Object.values(summary.skippedByReason).reduce((a, b) => a + (b ?? 0), 0);
  if (skippedCount > 0) parts.push(`${skippedCount} skipped`);
  if (summary.failed > 0) parts.push(`${summary.failed} failed`);
  if (summary.truncated) parts.push("output limit reached");
  return parts.join("; ");
}

export async function runCompiledScan(opts: {
  workDir: string;
  /** The scan's source files (relative to workDir). */
  fileList: string[];
  scanType: string;
  signal?: AbortSignal;
  onProgress?: (message: string) => void;
  /** Called once decompiling starts, with the number of artifacts to decompile. */
  onStart?: (artifacts: number) => void | Promise<void>;
  config?: CompiledScanConfig;
  runner?: ToolRunner;
  log?: Log;
}): Promise<CompiledScanOutcome> {
  const config = opts.config ?? compiledScanConfig();
  const log = opts.log ?? logger;
  const run = opts.runner ?? spawnTool;
  const filter: PackageFilter = {
    skipThirdParty: config.skipThirdParty,
    excludePackages: config.excludePackages,
    includePackages: config.includePackages,
  };
  if (!config.enabled) return emptyOutcome();

  const outRootName = fs.existsSync(path.join(opts.workDir, DECOMPILED_DIR)) ? `${DECOMPILED_DIR}pepper` : DECOMPILED_DIR;
  const candidates = listCompiledCandidates({
    workDir: opts.workDir,
    fileList: opts.fileList,
    scanType: opts.scanType,
    skipThirdParty: config.skipThirdParty,
  });
  if (candidates.length === 0) return emptyOutcome();

  const discovery = discoverArtifacts({
    workDir: opts.workDir,
    candidates,
    sourceFiles: opts.fileList,
    maxArtifactBytes: config.maxArtifactBytes,
    maxArtifacts: config.maxArtifacts,
    filter,
  });
  const skipped = [...discovery.skipped];
  if (discovery.artifacts.length === 0) {
    const outcome = emptyOutcome(skipped);
    log.info({ skipped: outcome.summary.skippedByReason }, "Compiled artifacts found, none to decompile");
    return outcome;
  }

  const outRoot = path.join(opts.workDir, outRootName);
  const tmpRoot = path.join(opts.workDir, TMP_DIR);
  fs.mkdirSync(outRoot, { recursive: true });
  fs.mkdirSync(tmpRoot, { recursive: true });

  const queue: QueueItem[] = discovery.artifacts.map((a) => ({
    artifact: a,
    label: artifactLabel(a),
    input: path.join(opts.workDir, a.path),
    depth: 0,
  }));
  let artifactSlots = config.maxArtifacts - queue.length;
  const budget: Budget = { files: config.maxFiles, bytes: config.maxOutputBytes };
  const deadline = Date.now() + config.totalTimeoutMs;
  const records: DecompiledArtifactRecord[] = [];
  const files: string[] = [];
  const done: DecompiledArtifactSummary[] = [];
  const missingTools = new Set<string>();
  let failed = 0;
  let bytesAdded = 0;
  let truncated = false;
  let seq = 0;

  try {
    await opts.onStart?.(queue.length);
    opts.onProgress?.(`Decompiling ${pluralize(queue.length, "compiled artifact")}…`);
    log.info({ artifacts: queue.map((q) => q.label) }, "Decompiling compiled artifacts");

    for (let i = 0; i < queue.length; i++) {
      const item = queue[i];
      if (opts.signal?.aborted) break;
      if (Date.now() >= deadline) {
        skipped.push({ path: item.label, reason: "time-limit", detail: "decompile time budget for the scan used up" });
        continue;
      }
      if (budget.files <= 0 || budget.bytes <= 0) {
        truncated = true;
        skipped.push({ path: item.label, reason: "output-limit", detail: "decompiled-output limit for the scan reached" });
        continue;
      }

      seq++;
      const outDirRel = `${outRootName}/${seq}-${safeName(path.posix.basename(item.label) || "classes")}`;
      const outDir = path.join(opts.workDir, outDirRel);
      const tmpDir = path.join(tmpRoot, String(seq));
      fs.mkdirSync(outDir, { recursive: true });
      fs.mkdirSync(tmpDir, { recursive: true });

      let input = item.input;
      if (item.artifact.kind === "classes") {
        input = path.join(tmpDir, "classes");
        fs.mkdirSync(input, { recursive: true });
        stageClasses(opts.workDir, item.artifact.classes ?? [], input);
      }

      const cmd = buildDecompileCommand({ kind: item.artifact.kind, input, outDir, tmpDir, config, filter });
      if (missingTools.has(cmd.tool)) {
        skipped.push({ path: item.label, reason: "tool-missing", detail: `${cmd.tool} is not installed on this worker` });
        fs.rmSync(outDir, { recursive: true, force: true });
        continue;
      }
      opts.onProgress?.(`Decompiling ${item.label} (${i + 1}/${queue.length}) with ${cmd.tool}`);
      const started = Date.now();
      const result = await run({
        bin: cmd.bin,
        args: cmd.args,
        env: cmd.env,
        timeoutMs: Math.max(1000, Math.min(config.timeoutMs, deadline - Date.now())),
        signal: opts.signal,
      });
      fs.rmSync(tmpDir, { recursive: true, force: true });
      if (result.aborted || opts.signal?.aborted) break;
      if (result.spawnError) {
        missingTools.add(cmd.tool);
        log.warn({ tool: cmd.tool, bin: cmd.bin, err: result.spawnError }, "Decompiler not available; compiled artifacts of this kind are skipped");
        skipped.push({ path: item.label, reason: "tool-missing", detail: `${cmd.tool} is not installed on this worker` });
        fs.rmSync(outDir, { recursive: true, force: true });
        continue;
      }

      // Archives inside a JVM archive (a WAR in an EAR): decompile them as
      // artifacts of their own, unless they are bundled dependencies.
      let nestedQueued = 0;
      if (item.artifact.kind === "jvm") {
        for (const nested of walkFiles(outDir)) {
          const ext = path.posix.extname(nested.innerPath).toLowerCase();
          if (!NESTED_ARCHIVE_EXTENSIONS.has(ext)) continue;
          const nestedLabel = `${item.label}!/${nested.innerPath}`;
          const nestedAbs = path.join(outDir, nested.innerPath);
          if (config.skipThirdParty && isInDependencyDir(nested.innerPath)) {
            skipped.push({ path: nestedLabel, reason: "dependency" });
          } else if (item.depth + 1 > MAX_NESTING) {
            skipped.push({ path: nestedLabel, reason: "artifact-limit", detail: "archive nested too deeply" });
          } else if (nested.bytes > config.maxArtifactBytes) {
            skipped.push({ path: nestedLabel, reason: "too-large" });
          } else if (artifactSlots <= 0) {
            skipped.push({ path: nestedLabel, reason: "artifact-limit", detail: `more than ${config.maxArtifacts} artifacts in one scan` });
          } else {
            const staged = path.join(tmpRoot, `nested-${seq}-${queue.length}${ext}`);
            fs.renameSync(nestedAbs, staged);
            artifactSlots--;
            nestedQueued++;
            queue.push({
              artifact: { path: nestedLabel, kind: "jvm", size: nested.bytes },
              label: nestedLabel,
              input: staged,
              depth: item.depth + 1,
            });
          }
        }
      }

      const trim = trimOutput(outDir, filter, budget, config.maxFileBytes);
      if (trim.overBudget > 0) truncated = true;
      const sourceFiles = trim.kept.filter((f) => /\.(java|kt|cs|vb)$/i.test(f.innerPath)).length;

      // A container whose content is all in nested archives (an EAR) has nothing of its own.
      if (trim.kept.length === 0 && result.code === 0 && nestedQueued > 0) {
        fs.rmSync(outDir, { recursive: true, force: true });
        continue;
      }
      if (trim.kept.length === 0 || (sourceFiles === 0 && result.code !== 0)) {
        failed++;
        const reason: SkipReason = result.timedOut ? "timeout" : "failed";
        const detail = result.timedOut
          ? `${cmd.tool} did not finish within ${Math.round(config.timeoutMs / 1000)}s`
          : trim.kept.length === 0 && result.code === 0
            ? "nothing to scan after excluding third-party code"
            : `${cmd.tool} exited with code ${result.code}${result.stderr ? `: ${stderrExcerpt(result.stderr)}` : ""}`;
        skipped.push({ path: item.label, reason, detail });
        log.warn({ artifact: item.label, tool: cmd.tool, code: result.code, timedOut: result.timedOut, stderr: stderrExcerpt(result.stderr) }, "Decompile produced no usable source");
        fs.rmSync(outDir, { recursive: true, force: true });
        continue;
      }

      const partial = result.code !== 0 || result.timedOut;
      records.push({ artifact: item.label, outDir: outDirRel, tool: cmd.tool });
      for (const f of trim.kept) {
        files.push(`${outDirRel}/${f.innerPath}`);
        bytesAdded += f.bytes;
      }
      const notes: string[] = [];
      if (result.timedOut) notes.push("timed out; partial output kept");
      else if (result.code !== 0) notes.push(`${cmd.tool} reported errors; partial output kept`);
      if (trim.overBudget > 0) notes.push(`${trim.overBudget} files over the output limit not scanned`);
      done.push({
        artifact: item.label,
        tool: cmd.tool,
        files: trim.kept.length,
        status: partial ? "partial" : "ok",
        ...(notes.length ? { note: notes.join("; ") } : {}),
      });
      log.info(
        {
          artifact: item.label,
          tool: cmd.tool,
          kept: trim.kept.length,
          sourceFiles,
          droppedThirdPartyOrBinary: trim.dropped,
          overBudget: trim.overBudget,
          ms: Date.now() - started,
          exitCode: result.code,
        },
        "Artifact decompiled",
      );
    }
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }

  const summary = summarize(done, skipped, failed, files.length, bytesAdded, truncated);
  opts.onProgress?.(describeOutcome(summary));
  return { files, pathMap: new DecompiledPathMap(records), summary };
}
