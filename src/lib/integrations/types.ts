export type IntegrationKind =
  | "JIRA"
  | "SLACK"
  | "SIEM"
  | "CODE_SIGNING"
  | "WEBHOOK";

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

export type WebhookEvent =
  | "scan.completed"
  | "scan.gate_failed"
  | "finding.new.critical"
  | "finding.new.high";

export type WebhookPayloadTemplate =
  | "default"
  | "slack"
  | "teams"
  | "pagerduty"
  | "linear";

export interface WebhookConfig {
  /** Target URL to POST to. */
  webhookUrl: string;
  /** Which events should trigger this webhook. */
  events: WebhookEvent[];
  /** Optional custom HTTP headers (e.g. auth tokens). */
  headers?: Array<{ key: string; value: string }>;
  /** Only fire when the scan has at least one finding at this severity or above. */
  minSeverity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  /** Limit to specific project IDs; empty / omitted = all projects. */
  projectIds?: string[];
  /** Pre-built payload shape. "default" sends Pepper's native JSON. */
  payloadTemplate?: WebhookPayloadTemplate;
  /** Optional HMAC-SHA256 signing secret — added as X-Pepper-Signature header. */
  secret?: string;
}

export type IntegrationConfigData =
  | { kind: "JIRA"; config: JiraConfig }
  | { kind: "SLACK"; config: SlackConfig }
  | { kind: "SIEM"; config: SiemConfig }
  | { kind: "WEBHOOK"; config: WebhookConfig };
