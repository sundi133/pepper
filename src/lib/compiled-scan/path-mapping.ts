/**
 * Mapping decompiled files back to the artifact they came from, so a finding
 * reads `app.apk!/com/example/Login.java:42` instead of a path in the
 * worker's scratch folder.
 */
import type { RawFinding } from "@/scanners/types";
import { DECOMPILED_PATH_SEPARATOR } from "./finding-origin";

export interface DecompiledArtifactRecord {
  /** Display name of the artifact: its repository path, or `outer.ear!/inner.war` when nested. */
  artifact: string;
  /** Work-dir-relative folder the artifact was decompiled into (forward slashes). */
  outDir: string;
  /** Decompiler that produced it. */
  tool: string;
}

export interface DecompiledOrigin {
  artifact: string;
  /** File inside the artifact, e.g. "com/example/Login.java". */
  innerPath: string;
  /** Work-dir-relative path the scanners saw. */
  decompiledPath: string;
  tool: string;
  /** `artifact!/innerPath` */
  displayPath: string;
}

const toPosix = (p: string) => p.replace(/\\/g, "/").replace(/^\.\//, "");

export class DecompiledPathMap {
  private readonly records: DecompiledArtifactRecord[];

  constructor(records: DecompiledArtifactRecord[] = []) {
    // Longest folder first, so a nested artifact's folder wins over its parent's.
    this.records = records
      .map((r) => ({ ...r, outDir: toPosix(r.outDir).replace(/\/+$/, "") }))
      .sort((a, b) => b.outDir.length - a.outDir.length);
  }

  get size(): number {
    return this.records.length;
  }

  resolve(filePath: string | undefined | null): DecompiledOrigin | null {
    if (!filePath || this.records.length === 0) return null;
    const p = toPosix(filePath);
    for (const r of this.records) {
      if (!p.startsWith(`${r.outDir}/`)) continue;
      const innerPath = p.slice(r.outDir.length + 1);
      if (!innerPath) return null;
      return {
        artifact: r.artifact,
        innerPath,
        decompiledPath: p,
        tool: r.tool,
        displayPath: `${r.artifact}${DECOMPILED_PATH_SEPARATOR}${innerPath}`,
      };
    }
    return null;
  }

  /**
   * The finding as it should be stored and shown: path rewritten to
   * `artifact!/file`, marked in metadata. Findings outside decompiled code
   * come back unchanged (same object).
   */
  mapFinding<T extends RawFinding>(finding: T): T {
    const origin = this.resolve(finding.filePath);
    if (!origin) return finding;
    return {
      ...finding,
      filePath: origin.displayPath,
      metadata: {
        ...(finding.metadata ?? {}),
        decompiledFrom: origin.artifact,
        decompiledFile: origin.innerPath,
        decompiledPath: origin.decompiledPath,
        decompiler: origin.tool,
      },
    };
  }
}
