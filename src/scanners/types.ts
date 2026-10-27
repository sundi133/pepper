export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScannerType =
  | "SAST_PATTERN"
  | "SAST_LLM"
  | "SCA"
  | "SECRETS_PATTERN"
  | "SECRETS_LLM"
  | "IAC"
  | "MALICIOUS_PKG"
  | "ZERO_DAY"
  | "CONTAINER"
  | "K8S";

export interface ScanContext {
  workDir: string;
  fileList: string[];
  /** When set (incremental PR scans), SCA / malicious-pkg use this instead of fileList. */
  scaFileList?: string[];
  /**
   * Source decompiled from compiled artifacts (lib/compiled-scan). Only the
   * source scanners (SAST and secrets) see these, added to their fileList;
   * dependency, IaC and container scanners keep the original list.
   */
  decompiledFileList?: string[];
  scanType: string;
  orgSettings: {
    llmProvider: string;
    llmBaseUrl: string;
    llmModel: string;
    llmApiKey?: string;
    enableLlmSast: boolean;
    enableLlmSecrets: boolean;
    osvApiUrl: string;
    vulnDbMode: "online" | "mirror" | "offline";
    orgId?: string;
    containerRegistryType?: string;
    containerRegistryUsername?: string;
    containerRegistryPassword?: string;
    containerRegistryRegion?: string;
  };
  scanId?: string;
  /**
   * The single uploaded compiled/binary artifact's workDir-relative name, when
   * the scan source is one uploaded artifact. The agent deep scan keys off this
   * (never files found inside a source archive or repo), so it only ever runs
   * for a binary upload. Undefined for source-archive, repo and git scans.
   */
  uploadedArtifact?: string;
  signal?: AbortSignal;
  waitIfPaused?: () => Promise<void>;
  onProgress?: (message: string) => void;
  onScannerComplete?: (
    scannerName: string,
    findings: RawFinding[],
  ) => Promise<void>;
  /** A scanner threw: record it as failed with the reason instead of dropping it silently. */
  onScannerFailed?: (scannerName: string, message: string) => Promise<void>;
  /**
   * Report vulnerabilities that triage ruled out. Kept separate from findings
   * so they reach the VEX document without appearing in the findings list.
   */
  onSuppressedVulnerabilities?: (
    suppressed: SuppressedVulnerability[],
  ) => void;
  /** Called with intermediate findings as LLM batches complete (before scanner finishes) */
  onBatchFindings?: (
    scannerName: string,
    findings: RawFinding[],
  ) => Promise<void>;
  /** Called when a higher-quality finding (e.g. AI) supersedes an earlier finding (e.g. pattern) */
  onFindingsReplaced?: (
    replacements: Array<{ superseded: RawFinding; replacement: RawFinding }>,
  ) => Promise<void>;
  /**
   * A scanner's full model reasoning trace, for the processor to persist so
   * developers can read how the AI reached its findings. Called once per
   * scanner that produces reasoning (the mobile review streams it live via
   * onProgress and stores the whole trace here).
   */
  onReasoning?: (scannerName: string, reasoning: string) => Promise<void>;
  /**
   * Visible status for the agent deep scan (scanners/mobile-agent): running (+
   * sandbox id), completed, incomplete or failed. Persisted by the processor to
   * scannerProgress.AGENT_SCAN so it survives the ephemeral sandbox and shows on
   * the scan page. Only the agent scanner calls it.
   */
  onAgentStatus?: (entry: {
    status: "RUNNING" | "DONE";
    outcome?: "completed" | "incomplete" | "failed" | "skipped";
    sandboxId?: string;
    /** Raw pre-dedup count the agent reported; the banner shows the deduped count. */
    reported?: number;
    note?: string;
  }) => Promise<void>;
}

/** @see scanners/shared/finding-metadata.ts */
export type FindingMetadata = import("./shared/finding-metadata").FindingMetadata;

export interface RawFinding {
  scanner: ScannerType;
  severity: SeverityLevel;
  title: string;
  description: string;
  filePath?: string;
  startLine?: number;
  endLine?: number;
  snippet?: string;
  ruleId?: string;
  cweId?: string;
  cveId?: string;
  confidence?: number;
  metadata?: FindingMetadata & Record<string, unknown>;
  masked?: boolean;
}

export interface ScannerPlugin {
  name: string;
  scan(ctx: ScanContext): Promise<RawFinding[]>;
}

export interface Dependency {
  name: string;
  version: string;
  ecosystem: string;
  isDev?: boolean;
  lockfileVersion?: string;
  sourceFile?: string; // The manifest file this dependency came from (e.g., package.json)
  /**
   * Declared SPDX license expressions (e.g. ["Apache-2.0 OR MIT"]), resolved
   * from deps.dev. Undefined means "not looked up or unavailable" — never
   * "unlicensed".
   */
  licenses?: string[];
}

export interface DependencyParser {
  filePatterns: string[];
  ecosystem: string;
  parse(content: string, filePath: string): Dependency[];
}

export interface Chunk {
  content: string;
  startLine: number;
  endLine: number;
  filePath: string;
  /** True when this chunk is the entire file (whole-file review mode). */
  wholeFile?: boolean;
}

export interface PatternRule {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  cweId?: string;
  languages: string[];
  pattern: RegExp;
  negative?: RegExp;
}

export interface SecretPattern {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  pattern: RegExp;
  allowlist?: RegExp[];
}

/**
 * A vulnerability that automated triage determined does not affect this project.
 *
 * These are deliberately NOT stored as findings — surfacing them would undo the
 * noise reduction triage exists to provide. They are carried out of the scan so
 * they can be asserted in a VEX document instead: "we saw this CVE and
 * determined it does not affect us, and here is why" is exactly what a VEX
 * `not_affected` statement is for, and it is the half of the evidence that is
 * otherwise lost.
 */
export interface SuppressedVulnerability {
  /** CVE or advisory identifier. */
  vulnerabilityId: string;
  /** Advisory id when it differs from vulnerabilityId (e.g. the GHSA). */
  advisoryId?: string;
  title?: string;
  severity?: SeverityLevel;
  packageName?: string;
  packageVersion?: string;
  ecosystem?: string;
  /** Why triage concluded it does not apply. Becomes the VEX justification. */
  reason: string;
  /** What produced the decision, for audit disclosure in the VEX. */
  assessedBy: "automated-triage";
  /** Evidence carried forward so the decision can be reviewed later. */
  metadata?: Record<string, unknown>;
}

export interface ScanResult {
  findings: RawFinding[];
  dependencies: Dependency[];
  filesScanned: number;
  depsScanned: number;
  /** Vulnerabilities triage ruled out, for VEX. Never persisted as findings. */
  suppressed: SuppressedVulnerability[];
}
