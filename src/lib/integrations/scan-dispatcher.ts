import { prisma } from "@/lib/prisma";
import { decryptSecret } from "@/lib/token-encryption";
import {
  notifySlackScanComplete,
  type SlackScanCompleteInput,
} from "./slack";
import { createJiraIssueForFinding, shouldOpenJiraTicket } from "./jira";
import { forwardToSiem, type SiemFindingEvent } from "./siem";
import type { JiraConfig, SlackConfig, SiemConfig } from "./types";

interface DecryptedRow<TKind extends string, TConfig> {
  id: string;
  name: string;
  kind: TKind;
  config: TConfig;
}

async function loadEnabled<T>(orgId: string, kind: string) {
  const rows = await prisma.integrationConfig.findMany({
    where: { organizationId: orgId, kind: kind as never, enabled: true },
  });
  const out: DecryptedRow<string, T>[] = [];
  for (const r of rows) {
    try {
      out.push({
        id: r.id,
        name: r.name,
        kind: r.kind,
        config: JSON.parse(decryptSecret(r.configEnc)) as T,
      });
    } catch {
      /* skip un-decryptable row */
    }
  }
  return out;
}

function scanWebUrl(scanId: string): string | undefined {
  const base =
    process.env.NEXTAUTH_URL ||
    process.env.APP_URL ||
    process.env.NEXT_PUBLIC_APP_URL;
  return base ? `${base.replace(/\/+$/, "")}/scans/${scanId}` : undefined;
}

/**
 * Fire Slack notifications, open Jira tickets for severe findings, and
 * forward all findings to SIEM. Best-effort; failures are swallowed and
 * logged via console (caller has its own pino logger context).
 */
export async function dispatchScanCompleteIntegrations(scanId: string) {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    select: {
      id: true,
      branch: true,
      criticalCount: true,
      highCount: true,
      mediumCount: true,
      lowCount: true,
      infoCount: true,
      gateResult: true,
      project: { select: { name: true, organizationId: true } },
    },
  });
  if (!scan?.project) return;
  const orgId = scan.project.organizationId;
  const scanUrl = scanWebUrl(scan.id);

  const slackInput: SlackScanCompleteInput = {
    projectName: scan.project.name,
    scanId: scan.id,
    scanUrl,
    branch: scan.branch,
    severityCounts: {
      critical: scan.criticalCount,
      high: scan.highCount,
      medium: scan.mediumCount,
      low: scan.lowCount,
      info: scan.infoCount,
    },
    gateResult: scan.gateResult as "PASSED" | "FAILED" | "PENDING",
  };

  // ----- Slack -----
  const slacks = await loadEnabled<SlackConfig>(orgId, "SLACK");
  await Promise.allSettled(
    slacks.map((s) =>
      notifySlackScanComplete(s.config, slackInput).catch((e) =>
        console.warn("[integrations] Slack notify failed:", e),
      ),
    ),
  );

  // ----- Jira (per-finding, severe only) -----
  const jiras = await loadEnabled<JiraConfig>(orgId, "JIRA");
  if (jiras.length > 0) {
    const severeFindings = await prisma.finding.findMany({
      where: {
        scanId: scan.id,
        severity: { in: ["CRITICAL", "HIGH"] },
        status: "OPEN",
      },
      take: 25,
    });
    for (const jira of jiras) {
      for (const f of severeFindings) {
        if (
          !shouldOpenJiraTicket(jira.config, f.severity as "CRITICAL" | "HIGH")
        )
          continue;
        try {
          await createJiraIssueForFinding(jira.config, {
            pepperFindingId: f.id,
            title: f.title,
            severity: f.severity as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            description: f.description,
            filePath: f.filePath,
            line: f.startLine,
            ruleId: f.ruleId,
            cveId: f.cveId,
            cweId: f.cweId,
            scanId: f.scanId,
            scanUrl,
          });
        } catch (e) {
          console.warn("[integrations] Jira create failed:", e);
        }
      }
    }
  }

  // ----- SIEM (all findings, batched) -----
  const siems = await loadEnabled<SiemConfig>(orgId, "SIEM");
  if (siems.length > 0) {
    const findings = await prisma.finding.findMany({
      where: { scanId: scan.id },
      select: {
        scanner: true,
        severity: true,
        title: true,
        ruleId: true,
        cveId: true,
        cweId: true,
        filePath: true,
        startLine: true,
        createdAt: true,
      },
    });
    const events: SiemFindingEvent[] = findings.map((f) => ({
      scanId: scan.id,
      organizationId: orgId,
      projectName: scan.project!.name,
      severity: f.severity as SiemFindingEvent["severity"],
      title: f.title,
      ruleId: f.ruleId,
      cveId: f.cveId,
      cweId: f.cweId,
      filePath: f.filePath,
      line: f.startLine,
      scanner: f.scanner,
      detectedAt: f.createdAt.toISOString(),
    }));
    await Promise.allSettled(
      siems.map((s) =>
        forwardToSiem(s.config, events).catch((e) =>
          console.warn("[integrations] SIEM forward failed:", e),
        ),
      ),
    );
  }
}
