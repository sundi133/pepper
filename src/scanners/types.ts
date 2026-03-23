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
  orgSettings: {
    llmProvider: string;
    llmBaseUrl: string;
    llmModel: string;
    llmApiKey?: string;
    enableLlmSast: boolean;
    enableLlmSecrets: boolean;
    osvApiUrl: string;
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
