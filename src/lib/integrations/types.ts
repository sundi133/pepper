export type IntegrationKind =
  | "JIRA"
  | "SLACK"
  | "SIEM"
  | "CODE_SIGNING"
  | "WEBHOOK"
  | "AZURE_BOARDS";

export type TicketSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface AzureBoardsConfig {
  /**
   * Azure DevOps Server base up to (not including) the collection, e.g.
   * `https://tfs.company.com/tfs`. Empty for Azure DevOps Services.
   */
  serverUrl?: string;
  /** Organization (Services) or collection (Server). */
  organization: string;
  /**
   * Team project the work items are created in. Empty = each repository's own
   * Azure DevOps project (repositories imported from Azure DevOps only).
   */
  project?: string;
  /**
   * Personal Access Token with Work Items (Read & write). Empty = reuse the
   * organization's Azure DevOps repository connection.
   */
  pat?: string;
  /** Work item type, defaults to "Bug" ("Issue" on the Basic process). */
  workItemType?: string;
  /** e.g. `Project\\Security`. Defaults to the project's root area. */
  areaPath?: string;
  iterationPath?: string;
  /** Default assignee (email or display name). */
  assignedTo?: string;
  /** Extra tags, added to the `pepper` / severity tags. */
  tags?: string[];
  /**
   * File a work item automatically when a scan finds new issues at these
   * severities. Empty = manual only (Raise ticket in the finding panel).
   */
  autoCreateSeverities?: TicketSeverity[];
  /**
   * When later scans no longer detect the issue, move the work item to this state
   * (e.g. "Resolved", "Done"). Empty = only add a comment.
   */
  fixedState?: string;
  /** REST api-version override (Azure DevOps Server 2020 needs "6.0"). */
  apiVersion?: string;
}

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
  | { kind: "WEBHOOK"; config: WebhookConfig }
  | { kind: "AZURE_BOARDS"; config: AzureBoardsConfig };
