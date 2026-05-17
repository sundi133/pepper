import type { JiraConfig } from "./types";

const DEFAULT_PRIORITY_MAP: Record<
  "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  string
> = {
  CRITICAL: "Highest",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};

interface JiraFindingInput {
  pepperFindingId: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  filePath?: string | null;
  line?: number | null;
  ruleId?: string | null;
  cveId?: string | null;
  cweId?: string | null;
  scanId: string;
  scanUrl?: string;
}

export interface JiraCreateResult {
  /** Jira issue key, e.g. "SEC-1234". */
  key: string;
  /** Full self URL of the issue. */
  url: string;
}

function basicAuth(email: string, token: string): string {
  return `Basic ${Buffer.from(`${email}:${token}`).toString("base64")}`;
}

function buildIssueBody(finding: JiraFindingInput): string {
  const parts: string[] = [];
  parts.push(finding.description.trim());
  parts.push("");
  parts.push("---");
  parts.push("");
  parts.push(`*Pepper finding:* ${finding.pepperFindingId}`);
  if (finding.scanUrl) parts.push(`*Scan:* ${finding.scanUrl}`);
  if (finding.filePath) {
    const where = finding.line
      ? `${finding.filePath}:${finding.line}`
      : finding.filePath;
    parts.push(`*Location:* \`${where}\``);
  }
  if (finding.ruleId) parts.push(`*Rule:* ${finding.ruleId}`);
  if (finding.cveId) parts.push(`*CVE:* ${finding.cveId}`);
  if (finding.cweId) parts.push(`*CWE:* ${finding.cweId}`);
  return parts.join("\n");
}

export async function createJiraIssueForFinding(
  config: JiraConfig,
  finding: JiraFindingInput,
): Promise<JiraCreateResult> {
  const priorityMap = { ...DEFAULT_PRIORITY_MAP, ...(config.priorityMap || {}) };
  const issueType = config.issueType || "Bug";
  const priority =
    finding.severity === "INFO"
      ? priorityMap.LOW
      : priorityMap[finding.severity];

  const body = {
    fields: {
      project: { key: config.projectKey },
      summary: `[${finding.severity}] ${finding.title}`,
      issuetype: { name: issueType },
      priority: priority ? { name: priority } : undefined,
      description: buildIssueBody(finding),
      labels: [
        "pepper",
        `pepper-severity-${finding.severity.toLowerCase()}`,
        ...(finding.cveId ? [finding.cveId] : []),
      ],
    },
  };

  const url = `${config.baseUrl.replace(/\/+$/, "")}/rest/api/3/issue`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: basicAuth(config.email, config.apiToken),
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Jira create failed (${res.status}): ${text.slice(0, 300)}`);
  }
  const data = (await res.json()) as { key: string; self: string };
  return {
    key: data.key,
    url: `${config.baseUrl.replace(/\/+$/, "")}/browse/${data.key}`,
  };
}

export function shouldOpenJiraTicket(
  config: JiraConfig,
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
): boolean {
  if (severity === "INFO") return false;
  const allowed = config.openForSeverities || ["CRITICAL", "HIGH"];
  return allowed.includes(severity);
}
