/**
 * Which uploaded artifacts the agent deep scan handles. Keyed off the uploaded
 * file's extension only — never the files discovered inside a source archive or
 * repo — so the agent is scoped to single compiled/binary uploads and never
 * touches source/repo scans.
 *
 * The set matches the compiled/binary types the normal pipeline recognises
 * (see src/lib/compiled-scan), minus loose `.class` files (those are scanned as
 * a group, not a single uploaded artifact).
 */
const AGENT_ARTIFACT_EXTENSIONS = new Set([
  ".apk",
  ".aab",
  ".ipa",
  ".dex",
  ".jar",
  ".war",
  ".ear",
  ".dll",
  ".exe",
]);

/** True when `fileName` is an uploaded artifact the agent deep scan reviews. */
export function isAgentArtifact(fileName: string | null | undefined): boolean {
  const m = fileName?.toLowerCase().match(/\.[a-z0-9]+$/);
  return !!m && AGENT_ARTIFACT_EXTENSIONS.has(m[0]);
}

/** Scan types where LLM SAST (and so the agent scanner) runs; mirrors getScanners' `includeSast`. */
const AGENT_SCAN_TYPES = new Set(["FULL", "SAST_ONLY", "INCREMENTAL"]);

/**
 * Whether the agent deep scan should OWN this upload — i.e. be the sole
 * reviewer, with the local decompile + rule-based scanners skipped. True only
 * when the scan source is a single uploaded binary artifact, the agent scanner
 * will actually run (LLM SAST on, a SAST scan type), and the agent is
 * configured. Source-archive and repo scans have no uploaded artifact, so this
 * is false and they are never touched; an unconfigured instance is also false,
 * so binaries fall back to the normal pipeline.
 */
export function agentOwnsUpload(opts: {
  uploadedArtifact?: string | null;
  scanType: string;
  enableLlmSast: boolean;
  configured: boolean;
}): boolean {
  return (
    isAgentArtifact(opts.uploadedArtifact) &&
    AGENT_SCAN_TYPES.has(opts.scanType) &&
    opts.enableLlmSast === true &&
    opts.configured
  );
}
