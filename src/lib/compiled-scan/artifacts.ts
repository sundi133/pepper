/**
 * Finding the compiled artifacts in a checkout and deciding which ones to
 * decompile. Nothing here runs a decompiler; see decompile.ts.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import {
  detectPeFile,
  isDexHeader,
  isZipHeader,
  listZipEntries,
  readClassName,
  readHead,
} from "./binary-format";
import { isInDependencyDir, isThirdPartyAssembly, type PackageFilter } from "./third-party";

export type ArtifactKind = "jvm" | "android" | "dotnet" | "classes";

const EXTENSION_KIND: Record<string, "jvm" | "android" | "pe" | "class"> = {
  ".jar": "jvm",
  ".war": "jvm",
  ".ear": "jvm",
  ".apk": "android",
  ".aab": "android",
  ".dex": "android",
  ".dll": "pe",
  ".exe": "pe",
  ".class": "class",
};

export function compiledExtensionOf(relPath: string): string | null {
  const ext = path.extname(relPath).toLowerCase();
  return ext in EXTENSION_KIND ? ext : null;
}

export interface CompiledArtifact {
  /** Repository-relative path; for a group of loose classes, their class root folder ("" = scan root). */
  path: string;
  kind: ArtifactKind;
  size: number;
  /** Loose classes: each file and the class it defines ("com/example/Login"). */
  classes?: Array<{ path: string; className: string }>;
}

export type SkipReason =
  | "dependency"
  | "build-output"
  | "source-present"
  | "third-party"
  | "native"
  | "unrecognized"
  | "too-large"
  | "artifact-limit"
  | "output-limit"
  | "time-limit"
  | "tool-missing"
  | "timeout"
  | "failed"
  | "disabled";

export interface SkipNote {
  path: string;
  reason: SkipReason;
  detail?: string;
}

export interface DiscoveryOptions {
  workDir: string;
  /** Repository-relative paths that may be compiled artifacts. */
  candidates: string[];
  /** The scan's source files, used to recognise build output of source that is already scanned. */
  sourceFiles: string[];
  maxArtifactBytes: number;
  maxArtifacts: number;
  filter: PackageFilter;
}

export interface DiscoveryResult {
  artifacts: CompiledArtifact[];
  skipped: SkipNote[];
}

/** Folders build tools write their output to. */
const BUILD_OUTPUT_DIRS = new Set(["target", "build", "out", "bin", "obj", "dist"]);

const JVM_SOURCE = /\.(java|kt|kts|scala|groovy)$/i;
const DOTNET_SOURCE = /\.(cs|vb|fs)$/i;

const toPosix = (p: string) => p.replace(/\\/g, "/");

function inBuildOutputDir(relPath: string): boolean {
  return toPosix(relPath)
    .split("/")
    .slice(0, -1)
    .some((d) => BUILD_OUTPUT_DIRS.has(d.toLowerCase()));
}

/** Shallow paths first, then alphabetical: top-level deliverables win the artifact limit. */
function byDepthThenName(a: string, b: string): number {
  const da = a.split("/").length;
  const db = b.split("/").length;
  return da !== db ? da - db : a.localeCompare(b);
}

const MAX_CLASS_FILE_BYTES = 8 * 1024 * 1024;
/** An archive may unpack to at most this multiple of the artifact size limit (zip bomb guard). */
const MAX_UNPACK_RATIO = 10;

export function discoverArtifacts(opts: DiscoveryOptions): DiscoveryResult {
  const skipped: SkipNote[] = [];
  const artifacts: CompiledArtifact[] = [];

  const sources = opts.sourceFiles.map(toPosix);
  const hasJvmSource = sources.some((s) => JVM_SOURCE.test(s));
  const hasDotnetSource = sources.some((s) => DOTNET_SOURCE.test(s));
  // "Login" → source paths without extension, for matching loose classes to their source.
  const jvmSourceByName = new Map<string, string[]>();
  for (const s of sources) {
    if (!JVM_SOURCE.test(s)) continue;
    const noExt = s.replace(/\.[^./]+$/, "");
    const name = noExt.slice(noExt.lastIndexOf("/") + 1);
    const list = jvmSourceByName.get(name) ?? [];
    list.push(noExt);
    jvmSourceByName.set(name, list);
  }
  const sourceExistsFor = (className: string): boolean => {
    const outer = className.split("$")[0];
    const simple = outer.slice(outer.lastIndexOf("/") + 1);
    return (jvmSourceByName.get(simple) ?? []).some((s) => s === outer || s.endsWith(`/${outer}`));
  };

  const classGroups = new Map<string, Array<{ path: string; className: string }>>();
  const candidates = [...new Set(opts.candidates.map(toPosix))].sort(byDepthThenName);

  for (const rel of candidates) {
    const ext = compiledExtensionOf(rel);
    if (!ext) continue;
    const family = EXTENSION_KIND[ext];
    const abs = path.join(opts.workDir, rel);

    if (opts.filter.skipThirdParty && isInDependencyDir(rel)) {
      skipped.push({ path: rel, reason: "dependency" });
      continue;
    }
    const sourceAlreadyScanned = family === "pe" ? hasDotnetSource : hasJvmSource;
    if (inBuildOutputDir(rel) && sourceAlreadyScanned) {
      skipped.push({ path: rel, reason: "build-output", detail: "build output of source code already in this scan" });
      continue;
    }

    let size: number;
    try {
      const st = fs.lstatSync(abs);
      if (!st.isFile()) continue;
      size = st.size;
    } catch {
      continue;
    }
    if (size > opts.maxArtifactBytes) {
      skipped.push({
        path: rel,
        reason: "too-large",
        detail: `${Math.round(size / 1024 / 1024)} MB exceeds the ${Math.round(opts.maxArtifactBytes / 1024 / 1024)} MB limit`,
      });
      continue;
    }

    if (family === "class") {
      let className: string | null = null;
      if (size <= MAX_CLASS_FILE_BYTES) {
        try {
          className = readClassName(fs.readFileSync(abs));
        } catch {
          className = null;
        }
      }
      if (!className) {
        skipped.push({ path: rel, reason: "unrecognized", detail: "not a Java class file" });
        continue;
      }
      if (sourceExistsFor(className)) {
        skipped.push({ path: rel, reason: "source-present", detail: "the class's source file is already in this scan" });
        continue;
      }
      const suffix = `${className}.class`;
      const root =
        rel === suffix ? "" : rel.endsWith(`/${suffix}`) ? rel.slice(0, -suffix.length - 1) : path.posix.dirname(rel);
      const key = root === "." ? "" : root;
      const group = classGroups.get(key) ?? [];
      group.push({ path: rel, className });
      classGroups.set(key, group);
      continue;
    }

    if (family === "pe") {
      if (isThirdPartyAssembly(path.posix.basename(rel), opts.filter)) {
        skipped.push({ path: rel, reason: "third-party", detail: "well-known library assembly (covered by SCA)" });
        continue;
      }
      const pe = detectPeFile(abs);
      if (pe === "native") {
        skipped.push({
          path: rel,
          reason: "native",
          detail: "native machine code (no .NET metadata, or a single-file bundle); it cannot be decompiled to source",
        });
        continue;
      }
      if (pe === "not-pe") {
        skipped.push({ path: rel, reason: "unrecognized", detail: "not a Windows PE file" });
        continue;
      }
      artifacts.push({ path: rel, kind: "dotnet", size });
      continue;
    }

    let head: Buffer;
    try {
      head = readHead(abs, 16);
    } catch {
      continue;
    }
    const valid = ext === ".dex" ? isDexHeader(head) : isZipHeader(head);
    if (!valid) {
      skipped.push({ path: rel, reason: "unrecognized", detail: ext === ".dex" ? "not a DEX file" : "not a ZIP-based archive" });
      continue;
    }
    if (ext !== ".dex") {
      // Read the central directory first: a corrupt archive or a zip bomb
      // is reported here instead of failing (or filling the disk) in the decompiler.
      const listing = listZipEntries(abs);
      if (!listing) {
        skipped.push({ path: rel, reason: "unrecognized", detail: "not a readable ZIP archive" });
        continue;
      }
      const maxUnpacked = opts.maxArtifactBytes * MAX_UNPACK_RATIO;
      if (listing.totalUncompressed > maxUnpacked) {
        skipped.push({
          path: rel,
          reason: "too-large",
          detail: `unpacks to ${Math.round(listing.totalUncompressed / 1024 / 1024)} MB (limit ${Math.round(maxUnpacked / 1024 / 1024)} MB)`,
        });
        continue;
      }
    }
    artifacts.push({ path: rel, kind: family === "android" ? "android" : "jvm", size });
  }

  for (const [root, classes] of [...classGroups.entries()].sort(([a], [b]) => byDepthThenName(a, b))) {
    let size = 0;
    for (const c of classes) {
      try {
        size += fs.statSync(path.join(opts.workDir, c.path)).size;
      } catch {
        // counted as zero
      }
    }
    artifacts.push({ path: root, kind: "classes", size, classes });
  }

  const kept = artifacts.slice(0, opts.maxArtifacts);
  for (const a of artifacts.slice(opts.maxArtifacts)) {
    skipped.push({
      path: artifactLabel(a),
      reason: "artifact-limit",
      detail: `more than ${opts.maxArtifacts} artifacts in one scan`,
    });
  }
  return { artifacts: kept, skipped };
}

/** How an artifact is named in findings and notes: its path, or its class folder. */
export function artifactLabel(a: Pick<CompiledArtifact, "path" | "kind">): string {
  if (a.kind === "classes") return a.path || "classes";
  return a.path;
}

const WALK_ALWAYS_SKIP = new Set([".git", ".svn", ".hg"]);
const WALK_DEPENDENCY_SKIP = new Set(["node_modules", "bower_components"]);

/**
 * Compiled-artifact candidates in a checkout. Unlike the source file list,
 * this looks inside build-output folders (target/, build/, dist/): that is
 * where a WAR or APK usually sits in an uploaded release bundle. PR scans
 * only consider the files the change touched.
 */
export function listCompiledCandidates(opts: {
  workDir: string;
  fileList: string[];
  scanType: string;
  skipThirdParty: boolean;
  /** Folders (relative) never walked, e.g. the decompiler's own output. */
  excludeDirs?: string[];
}): string[] {
  if (opts.scanType === "INCREMENTAL") {
    return opts.fileList.filter((f) => compiledExtensionOf(f) !== null).map(toPosix);
  }
  const exclude = new Set((opts.excludeDirs ?? []).map(toPosix));
  const out: string[] = [];
  const walk = (dir: string, prefix: string) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (WALK_ALWAYS_SKIP.has(entry.name) || exclude.has(rel)) continue;
        if (opts.skipThirdParty && WALK_DEPENDENCY_SKIP.has(entry.name)) continue;
        walk(path.join(dir, entry.name), rel);
      } else if (entry.isFile() && compiledExtensionOf(entry.name)) {
        out.push(rel);
      }
    }
  };
  walk(opts.workDir, "");
  return out;
}
