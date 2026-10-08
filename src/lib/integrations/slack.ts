import type { SlackConfig } from "./types";

export interface SlackScanCompleteInput {
  projectName: string;
  scanId: string;
  scanUrl?: string;
  branch?: string | null;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info?: number;
  };
  gateResult: "PASSED" | "FAILED" | "PENDING";
}

export interface SlackFindingInput {
  projectName: string;
  findingTitle: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  filePath?: string | null;
  line?: number | null;
  ruleId?: string | null;
  cweId?: string | null;
  scanUrl?: string;
}

const SEVERITY_EMOJI: Record<SlackFindingInput["severity"], string> = {
  CRITICAL: ":red_circle:",
  HIGH: ":large_orange_circle:",
  MEDIUM: ":large_yellow_circle:",
  LOW: ":large_blue_circle:",
  INFO: ":large_blue_circle:",
};

function severityEmoji(label: string, count: number): string {
  if (count === 0) return "";
  return `${label}: *${count}*`;
}

/** Post a single finding to a Slack incoming webhook. */
export async function notifySlackFinding(
  config: SlackConfig,
  input: SlackFindingInput,
): Promise<void> {
  const location = input.filePath
    ? input.line
      ? `<file://${input.filePath}:${input.line}|${input.filePath}:${input.line}>`
      : input.filePath
    : null;
  const idBits = [
    input.ruleId ? `Rule: \`${input.ruleId}\`` : null,
    input.cweId ? `CWE: \`${input.cweId}\`` : null,
  ]
    .filter(Boolean)
    .join("  |  ");

  const text = [
    `${SEVERITY_EMOJI[input.severity]} *[${input.severity}] ${input.findingTitle}*`,
    input.projectName ? `Repository: *${input.projectName}*` : null,
    location ? `Location: \`${location}\`` : null,
    idBits || null,
    (input.description || "").slice(0, 800),
    input.scanUrl ? `<${input.scanUrl}|View scan in Pepper>` : null,
  ]
    .filter((l): l is string => !!l)
    .join("\n");

  const payload: Record<string, unknown> = { text };
  if (config.channel) payload.channel = config.channel;

  const res = await fetch(config.webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Slack webhook failed (${res.status})`);
  }
}

export async function notifySlackScanComplete(
  config: SlackConfig,
  input: SlackScanCompleteInput,
): Promise<void> {
  const notifyOn = config.notifyOn || ["scan_complete", "gate_failed"];
  const isGateFail = input.gateResult === "FAILED";
  const hasCritical = input.severityCounts.critical > 0;

  const shouldNotify =
    notifyOn.includes("scan_complete") ||
    (notifyOn.includes("gate_failed") && isGateFail) ||
    (notifyOn.includes("critical_finding") && hasCritical);
  if (!shouldNotify) return;

  const sevLine = [
    severityEmoji(":red_circle: Critical", input.severityCounts.critical),
    severityEmoji(":large_orange_circle: High", input.severityCounts.high),
    severityEmoji(":large_yellow_circle: Medium", input.severityCounts.medium),
    severityEmoji(":large_blue_circle: Low", input.severityCounts.low),
  ]
    .filter(Boolean)
    .join("   ");

  const gateLine =
    input.gateResult === "FAILED"
      ? ":x: *Build gate failed*"
      : input.gateResult === "PASSED"
        ? ":white_check_mark: Build gate passed"
        : "Build gate pending";

  const text = `Pepper scan complete: *${input.projectName}*${
    input.branch ? ` on \`${input.branch}\`` : ""
  }\n${sevLine || "No findings."}\n${gateLine}${
    input.scanUrl ? `\n<${input.scanUrl}|View scan>` : ""
  }`;

  const payload: Record<string, unknown> = { text };
  if (config.channel) payload.channel = config.channel;

  const res = await fetch(config.webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(`Slack webhook failed (${res.status})`);
  }
}
