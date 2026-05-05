export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type ScannerType =
  | "SAST_PATTERN"
  | "SAST_LLM"
  | "SCA"
  | "SECRETS_PATTERN"
  | "SECRETS_LLM"
  | "IAC"
  | "MALICIOUS_PKG"
  | "ZERO_DAY";

export interface ScanContext {
  workDir: string;
  fileList: string[];
  scanType: string;
  /** Present when scan runs from worker job (live events, UI correlation). */
  scanId?: string;
  orgSettings: {
    llmProvider: string;
    llmBaseUrl: string;
    llmModel: string;
    llmApiKey?: string;
    enableLlmSast: boolean;
    enableLlmSecrets: boolean;
    osvApiUrl: string;
    orgId?: string;
  };
  signal?: AbortSignal;
  onProgress?: (message: string) => void;
  onScannerComplete?: (
    scannerName: string,
    findings: RawFinding[],
  ) => Promise<void>;
  /** Called with intermediate findings as LLM batches complete (before scanner finishes) */
  onBatchFindings?: (
    scannerName: string,
    findings: RawFinding[],
  ) => Promise<void>;
  /** Structured real-time events for polling/WebSocket-style UI (preferred over raw strings). */
  onEvent?: (event: ScanEvent) => void | Promise<void>;
}

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
  metadata?: Record<string, unknown>;
  masked?: boolean;
}

/** Structured real-time events for scan UI (worker + optional local runners). */
export type ScanEvent =
  | {
      type: "scan_started";
      scanId: string;
      timestamp: string;
      totalFiles?: number;
    }
  | {
      type: "extract_started";
      scanId: string;
      timestamp: string;
    }
  | {
      type: "extract_completed";
      scanId: string;
      timestamp: string;
      totalFiles: number;
      totalBytes: number;
    }
  | {
      type: "scanner_started";
      scanId: string;
      scanner:
        | "SAST_PATTERN"
        | "SAST_LLM"
        | "SECRET_SCAN"
        | "DEPENDENCY_SCAN"
        | string;
      timestamp: string;
    }
  | {
      type: "file_scanning";
      scanId: string;
      scanner: string;
      filePath: string;
      currentFile: number;
      totalFiles: number;
      timestamp: string;
    }
  | {
      type: "chunk_scanning";
      scanId: string;
      scanner: "SAST_LLM";
      filePath: string;
      chunkIndex: number;
      totalChunks: number;
      timestamp: string;
      llmModel?: string;
      llmProvider?: string;
    }
  | {
      type: "scan_progress";
      scanId: string;
      message: string;
      timestamp: string;
      scanner?: string;
      filesCompleted?: number;
      filesTotal?: number;
      findingsCount?: number;
    }
  | {
      type: "finding_found";
      scanId: string;
      scanner: string;
      finding: RawFinding;
      timestamp: string;
    }
  | {
      type: "scanner_completed";
      scanId: string;
      scanner: string;
      findingCount: number;
      timestamp: string;
    }
  | {
      type: "scan_completed";
      scanId: string;
      findingCount: number;
      timestamp: string;
    }
  | {
      type: "scan_failed";
      scanId: string;
      error: string;
      timestamp: string;
    };

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
  sourceFile?: string;
  sourceLine?: number;
  sourceSnippet?: string;
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

export interface ScanResult {
  findings: RawFinding[];
  dependencies: Dependency[];
  filesScanned: number;
  depsScanned: number;
}
