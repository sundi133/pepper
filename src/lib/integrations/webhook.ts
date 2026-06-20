import { createHmac } from "crypto";
import type { WebhookConfig, WebhookEvent } from "./types";

// ─── Payload types ────────────────────────────────────────────────────────────

export interface WebhookScanPayload {
  event: WebhookEvent;
  timestamp: string;
  scan: {
    id: string;
    projectName: string;
    branch: string | null;
    url: string | undefined;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    gateResult: string | null;
  };
  findings?: WebhookFindingPayload[];
}

export interface WebhookFindingPayload {
  id: string;
  severity: string;
  title: string;
  scanner: string;
  filePath: string | null;
  startLine: number | null;
  ruleId: string | null;
  cweId: string | null;
  cveId: string | null;
  riskScore: number | null;
  scanUrl: string | undefined;
}

// ─── Payload templates ────────────────────────────────────────────────────────

function buildDefaultPayload(data: WebhookScanPayload): unknown {
  return data;
}

function buildSlackPayload(data: WebhookScanPayload): unknown {
  const scan = data.scan;
  const gateEmoji =
    scan.gateResult === "FAILED" ? ":x:" : scan.gateResult === "PASSED" ? ":white_check_mark:" : ":hourglass:";

  const countLine = [
    scan.criticalCount > 0 ? `*${scan.criticalCount} critical*` : null,
    scan.highCount > 0 ? `${scan.highCount} high` : null,
    scan.mediumCount > 0 ? `${scan.mediumCount} medium` : null,
    scan.lowCount > 0 ? `${scan.lowCount} low` : null,
    scan.infoCount > 0 ? `${scan.infoCount} info` : null,
  ]
    .filter(Boolean)
    .join(", ") || "No findings";

  const eventLabel: Record<WebhookEvent, string> = {
    "scan.completed": "Scan completed",
    "scan.gate_failed": "Build gate FAILED",
    "finding.new.critical": "New critical finding",
    "finding.new.high": "New high-severity finding",
  };

  const blocks: unknown[] = [
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `${gateEmoji} *${eventLabel[data.event]}* — ${scan.projectName}${scan.branch ? ` (${scan.branch})` : ""}`,
      },
    },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Findings:*\n${countLine}` },
        ...(scan.gateResult
          ? [{ type: "mrkdwn", text: `*Gate:*\n${scan.gateResult}` }]
          : []),
      ],
    },
  ];

  if (scan.url) {
    blocks.push({
      type: "actions",
      elements: [
        {
          type: "button",
          text: { type: "plain_text", text: "View scan" },
          url: scan.url,
        },
      ],
    });
  }

  if (data.findings && data.findings.length > 0) {
    const findingList = data.findings
      .slice(0, 5)
      .map((f) => `• [${f.severity}] ${f.title}${f.filePath ? ` — \`${f.filePath}\`` : ""}`)
      .join("\n");
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `*Top findings:*\n${findingList}` },
    });
  }

  return { blocks };
}

function buildTeamsPayload(data: WebhookScanPayload): unknown {
  const scan = data.scan;
  const themeColor = scan.gateResult === "FAILED" ? "FF0000" : "36a64f";

  const facts = [
    { name: "Project", value: scan.projectName },
    scan.branch ? { name: "Branch", value: scan.branch } : null,
    { name: "Critical", value: String(scan.criticalCount) },
    { name: "High", value: String(scan.highCount) },
    { name: "Medium", value: String(scan.mediumCount) },
    { name: "Low", value: String(scan.lowCount) },
    scan.gateResult ? { name: "Gate", value: scan.gateResult } : null,
  ].filter(Boolean);

  const eventLabel: Record<WebhookEvent, string> = {
    "scan.completed": "Scan Completed",
    "scan.gate_failed": "Build Gate Failed",
    "finding.new.critical": "New Critical Finding",
    "finding.new.high": "New High-Severity Finding",
  };

  return {
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    themeColor,
    summary: `${eventLabel[data.event]} — ${scan.projectName}`,
    sections: [
      {
        activityTitle: `**${eventLabel[data.event]}**`,
        activitySubtitle: scan.projectName,
        facts,
        ...(scan.url
          ? {
              potentialAction: [
                {
                  "@type": "OpenUri",
                  name: "View scan",
                  targets: [{ os: "default", uri: scan.url }],
                },
              ],
            }
          : {}),
      },
    ],
  };
}

function buildPagerDutyPayload(data: WebhookScanPayload): unknown {
  const scan = data.scan;
  const severity =
    scan.criticalCount > 0
      ? "critical"
      : scan.highCount > 0
        ? "error"
        : scan.mediumCount > 0
          ? "warning"
          : "info";

  return {
    routing_key: "", // user must set this via custom header or replace in template
    event_action: "trigger",
    payload: {
      summary: `[Pepper] ${scan.projectName}: ${scan.criticalCount} critical, ${scan.highCount} high findings`,
      severity,
      source: scan.projectName,
      component: scan.branch ?? "main",
      group: "security",
      custom_details: {
        scanId: scan.id,
        criticalCount: scan.criticalCount,
        highCount: scan.highCount,
        gateResult: scan.gateResult,
        url: scan.url,
      },
    },
    ...(scan.url ? { links: [{ href: scan.url, text: "View scan in Pepper" }] } : {}),
  };
}

function buildLinearPayload(data: WebhookScanPayload): unknown {
  const scan = data.scan;
  const finding = data.findings?.[0];
  const title = finding
    ? `[Security] ${finding.severity}: ${finding.title}`
    : `[Security] Scan findings — ${scan.projectName}`;

  const body = [
    `**Project:** ${scan.projectName}${scan.branch ? ` (${scan.branch})` : ""}`,
    `**Findings:** ${scan.criticalCount} critical, ${scan.highCount} high, ${scan.mediumCount} medium`,
    scan.url ? `**Scan URL:** ${scan.url}` : null,
    finding ? `\n**Finding details:**\n- Title: ${finding.title}\n- File: ${finding.filePath ?? "N/A"}${finding.startLine ? `:${finding.startLine}` : ""}\n- Rule: ${finding.ruleId ?? "N/A"}` : null,
  ]
    .filter(Boolean)
    .join("\n");

  return {
    title,
    description: body,
    priority: scan.criticalCount > 0 ? 1 : scan.highCount > 0 ? 2 : 3,
  };
}

// ─── HMAC signing ─────────────────────────────────────────────────────────────

function signPayload(body: string, secret: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

// ─── Main fire function ───────────────────────────────────────────────────────

export interface FireWebhookResult {
  ok: boolean;
  status?: number;
  error?: string;
}

export async function fireWebhook(
  config: WebhookConfig,
  event: WebhookEvent,
  data: WebhookScanPayload,
): Promise<FireWebhookResult> {
  // Check event filter
  if (!config.events.includes(event)) {
    return { ok: true }; // not subscribed to this event
  }

  // Check min severity filter
  if (config.minSeverity) {
    const severityOrder = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const minIdx = severityOrder.indexOf(config.minSeverity);
    const hasSufficient =
      (minIdx <= severityOrder.indexOf("CRITICAL") && data.scan.criticalCount > 0) ||
      (minIdx <= severityOrder.indexOf("HIGH") && data.scan.highCount > 0) ||
      (minIdx <= severityOrder.indexOf("MEDIUM") && data.scan.mediumCount > 0) ||
      (minIdx <= severityOrder.indexOf("LOW") && data.scan.lowCount > 0) ||
      minIdx <= severityOrder.indexOf("INFO");
    if (!hasSufficient) return { ok: true };
  }

  // Build payload
  const template = config.payloadTemplate ?? "default";
  let payload: unknown;
  switch (template) {
    case "slack":
      payload = buildSlackPayload(data);
      break;
    case "teams":
      payload = buildTeamsPayload(data);
      break;
    case "pagerduty":
      payload = buildPagerDutyPayload(data);
      break;
    case "linear":
      payload = buildLinearPayload(data);
      break;
    default:
      payload = buildDefaultPayload(data);
  }

  const body = JSON.stringify(payload);

  // Build headers
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "User-Agent": "Pepper-Webhook/1.0",
  };
  for (const h of config.headers ?? []) {
    if (h.key && h.value) {
      headers[h.key] = h.value;
    }
  }
  if (config.secret) {
    headers["X-Pepper-Signature"] = `sha256=${signPayload(body, config.secret)}`;
  }

  try {
    const res = await fetch(config.webhookUrl, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      return { ok: false, status: res.status, error: text || `HTTP ${res.status}` };
    }
    return { ok: true, status: res.status };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Request failed",
    };
  }
}
