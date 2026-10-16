/**
 * Settings for the compiled-code scan, read from the environment at call time
 * so tests and long-running workers see the current values.
 *
 *   ENABLE_COMPILED_SCAN=false              turn the feature off (default on)
 *   COMPILED_SCAN_MAX_ARTIFACT_MB=200       skip larger artifacts
 *   COMPILED_SCAN_MAX_ARTIFACTS=25          artifacts decompiled per scan
 *   COMPILED_SCAN_MAX_FILES=5000            decompiled files kept per scan
 *   COMPILED_SCAN_MAX_OUTPUT_MB=200         decompiled bytes kept per scan
 *   COMPILED_SCAN_TIMEOUT_SECONDS=600       per artifact
 *   COMPILED_SCAN_TOTAL_TIMEOUT_SECONDS=1800  whole decompile step
 *   COMPILED_SCAN_SKIP_THIRD_PARTY=true     skip dependency folders, well-known
 *                                           library packages and assemblies
 *   COMPILED_SCAN_EXCLUDE_PACKAGES=""       more package / namespace prefixes to skip
 *   COMPILED_SCAN_INCLUDE_PACKAGES=""       prefixes never skipped (wins over excludes)
 *   COMPILED_SCAN_THREADS=2                 decompiler threads per artifact
 *   COMPILED_SCAN_JAVA_OPTS="-XX:MaxRAMPercentage=50"  JVM options for jadx / Vineflower
 *   JADX_BIN, VINEFLOWER_BIN, ILSPYCMD_BIN  tool overrides (default: on PATH)
 */

export interface CompiledScanConfig {
  enabled: boolean;
  maxArtifactBytes: number;
  maxArtifacts: number;
  maxFiles: number;
  maxOutputBytes: number;
  /** Largest single decompiled file kept (pattern scanners skip larger files anyway). */
  maxFileBytes: number;
  timeoutMs: number;
  totalTimeoutMs: number;
  skipThirdParty: boolean;
  excludePackages: string[];
  includePackages: string[];
  threads: number;
  javaOpts: string;
  jadxBin: string;
  vineflowerBin: string;
  ilspycmdBin: string;
}

type Env = Record<string, string | undefined>;

function positiveNumber(raw: string | undefined, fallback: number): number {
  const n = Number(raw?.trim());
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function flag(raw: string | undefined, fallback: boolean): boolean {
  const v = raw?.trim().toLowerCase();
  if (!v) return fallback;
  return !["false", "0", "no", "off"].includes(v);
}

/** "com.acme.vendor, org/foo" → ["com/acme/vendor", "org/foo"] */
export function parsePackageList(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((p) => p.trim().replace(/\\/g, "/").replace(/\./g, "/").replace(/^\/+|\/+$/g, ""))
    .filter(Boolean);
}

const MB = 1024 * 1024;

export function compiledScanConfig(env: Env = process.env): CompiledScanConfig {
  return {
    enabled: flag(env.ENABLE_COMPILED_SCAN, true),
    maxArtifactBytes: positiveNumber(env.COMPILED_SCAN_MAX_ARTIFACT_MB, 200) * MB,
    maxArtifacts: Math.floor(positiveNumber(env.COMPILED_SCAN_MAX_ARTIFACTS, 25)),
    maxFiles: Math.floor(positiveNumber(env.COMPILED_SCAN_MAX_FILES, 5000)),
    maxOutputBytes: positiveNumber(env.COMPILED_SCAN_MAX_OUTPUT_MB, 200) * MB,
    maxFileBytes: MB,
    timeoutMs: positiveNumber(env.COMPILED_SCAN_TIMEOUT_SECONDS, 600) * 1000,
    totalTimeoutMs: positiveNumber(env.COMPILED_SCAN_TOTAL_TIMEOUT_SECONDS, 1800) * 1000,
    skipThirdParty: flag(env.COMPILED_SCAN_SKIP_THIRD_PARTY, true),
    excludePackages: parsePackageList(env.COMPILED_SCAN_EXCLUDE_PACKAGES),
    includePackages: parsePackageList(env.COMPILED_SCAN_INCLUDE_PACKAGES),
    threads: Math.floor(positiveNumber(env.COMPILED_SCAN_THREADS, 2)),
    javaOpts: env.COMPILED_SCAN_JAVA_OPTS?.trim() || "-XX:MaxRAMPercentage=50",
    jadxBin: env.JADX_BIN?.trim() || "jadx",
    vineflowerBin: env.VINEFLOWER_BIN?.trim() || "vineflower",
    ilspycmdBin: env.ILSPYCMD_BIN?.trim() || "ilspycmd",
  };
}
