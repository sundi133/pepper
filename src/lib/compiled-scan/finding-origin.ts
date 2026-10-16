/**
 * Reading the "found in compiled code" marker on a finding. No Node imports:
 * the UI, exports and integrations use this too.
 *
 * A finding in decompiled code has its filePath rewritten to
 * `<artifact>!/<file inside it>` (e.g. `app.apk!/com/example/Login.java`,
 * nested: `app.ear!/web.war!/WEB-INF/classes/com/x/A.java`) and carries:
 *
 *   metadata.decompiledFrom   the artifact ("release/app.apk")
 *   metadata.decompiledFile   the decompiled file inside it ("com/example/Login.java")
 *   metadata.decompiler       the tool ("jadx", "vineflower", "ilspycmd")
 *   metadata.decompiledPath   where the file was in the scan's work dir
 *
 * Its line numbers refer to the decompiled source, not the original.
 */

export const DECOMPILED_PATH_SEPARATOR = "!/";

export interface DecompiledOriginInfo {
  artifact: string;
  file: string;
  decompiler?: string;
  /** Path of the decompiled file in the scan's work dir (worker-side only). */
  decompiledPath?: string;
}

export function decompiledOriginOf(metadata: unknown): DecompiledOriginInfo | null {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return null;
  const m = metadata as Record<string, unknown>;
  if (typeof m.decompiledFrom !== "string" || !m.decompiledFrom) return null;
  return {
    artifact: m.decompiledFrom,
    file: typeof m.decompiledFile === "string" ? m.decompiledFile : "",
    decompiler: typeof m.decompiler === "string" ? m.decompiler : undefined,
    decompiledPath: typeof m.decompiledPath === "string" ? m.decompiledPath : undefined,
  };
}

/** True for a finding located in decompiled code (by metadata, or by its `!/` path). */
export function isDecompiledFinding(finding: { filePath?: string | null; metadata?: unknown }): boolean {
  return decompiledOriginOf(finding.metadata) !== null || (finding.filePath ?? "").includes(DECOMPILED_PATH_SEPARATOR);
}

const DECOMPILER_LABELS: Record<string, string> = {
  jadx: "jadx",
  vineflower: "Vineflower",
  ilspycmd: "ILSpy",
};

export function decompilerLabel(tool: string | undefined): string | undefined {
  return tool ? (DECOMPILER_LABELS[tool] ?? tool) : undefined;
}
