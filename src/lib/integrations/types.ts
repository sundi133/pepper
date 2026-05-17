export type IntegrationKind =
  | "JIRA"
  | "SLACK"
  | "SIEM"
  | "DAST"
  | "CODE_SIGNING";

export interface JiraConfig {
  baseUrl: string;
  email: string;
  apiToken: string;
  projectKey: string;
  /** Optional issue type, defaults to "Bug". */
  issueType?: string;
  /** Map Pepper severity -> Jira priority name. */
  priorityMap?: Partial<Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW", string>>;
  /** Open Jira tickets automatically for these severities (default HIGH+). */
  openForSeverities?: ("CRITICAL" | "HIGH" | "MEDIUM" | "LOW")[];
}

export interface SlackConfig {
  /** Incoming webhook URL. */
  webhookUrl: string;
  /** Notify on gate failure, scan complete, or both. */
  notifyOn?: ("scan_complete" | "gate_failed" | "critical_finding")[];
  /** Optional channel override (only used by some Slack endpoints). */
  channel?: string;
}

export interface SiemConfig {
  /** Either an HTTPS endpoint (will POST JSON) or a syslog target host:port. */
  endpoint: string;
  format: "cef" | "leef" | "json";
  apiKey?: string;
}

export interface DapperIntegrationConfig {
  endpoint: string;
  apiKey?: string;
}

export type IntegrationConfigData =
  | { kind: "JIRA"; config: JiraConfig }
  | { kind: "SLACK"; config: SlackConfig }
  | { kind: "SIEM"; config: SiemConfig }
  | { kind: "DAST"; config: DapperIntegrationConfig };
