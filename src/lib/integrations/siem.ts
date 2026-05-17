import * as dgram from "dgram";
import * as net from "net";
import type { SiemConfig } from "./types";

export interface SiemFindingEvent {
  scanId: string;
  organizationId: string;
  projectName: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  title: string;
  ruleId?: string | null;
  cveId?: string | null;
  cweId?: string | null;
  filePath?: string | null;
  line?: number | null;
  scanner: string;
  detectedAt: string;
}

const PEPPER_DEVICE_VENDOR = "Pepper";
const PEPPER_DEVICE_PRODUCT = "Pepper-SAST";
const PEPPER_VERSION = "1.0";

function severityCefScore(s: SiemFindingEvent["severity"]): number {
  switch (s) {
    case "CRITICAL":
      return 10;
    case "HIGH":
      return 8;
    case "MEDIUM":
      return 5;
    case "LOW":
      return 3;
    default:
      return 1;
  }
}

function escapeCef(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/=/g, "\\=").replace(/\|/g, "\\|");
}

function escapeCefExt(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\r?\n/g, "\\n").replace(/=/g, "\\=");
}

/** ArcSight CEF 0 format. */
export function eventToCef(ev: SiemFindingEvent): string {
  const signature = escapeCef(ev.ruleId || ev.cveId || ev.title.slice(0, 64));
  const name = escapeCef(ev.title.slice(0, 200));
  const severity = severityCefScore(ev.severity);
  const ext = [
    `cs1Label=scanner cs1=${escapeCefExt(ev.scanner)}`,
    `cs2Label=scanId cs2=${escapeCefExt(ev.scanId)}`,
    `cs3Label=project cs3=${escapeCefExt(ev.projectName)}`,
    ev.cveId ? `cs4Label=cve cs4=${escapeCefExt(ev.cveId)}` : "",
    ev.cweId ? `cs5Label=cwe cs5=${escapeCefExt(ev.cweId)}` : "",
    ev.filePath ? `fname=${escapeCefExt(ev.filePath)}` : "",
    ev.line ? `cn1Label=line cn1=${ev.line}` : "",
    `rt=${Date.parse(ev.detectedAt) || Date.now()}`,
  ]
    .filter(Boolean)
    .join(" ");
  return `CEF:0|${escapeCef(PEPPER_DEVICE_VENDOR)}|${escapeCef(
    PEPPER_DEVICE_PRODUCT,
  )}|${escapeCef(PEPPER_VERSION)}|${signature}|${name}|${severity}|${ext}`;
}

/** IBM QRadar LEEF 2.0 format. */
export function eventToLeef(ev: SiemFindingEvent): string {
  const attrs = [
    `cat=${ev.scanner}`,
    `sev=${severityCefScore(ev.severity)}`,
    `scanId=${ev.scanId}`,
    `project=${ev.projectName}`,
    ev.cveId ? `cve=${ev.cveId}` : "",
    ev.cweId ? `cwe=${ev.cweId}` : "",
    ev.filePath ? `path=${ev.filePath}` : "",
    ev.line ? `line=${ev.line}` : "",
    `rule=${ev.ruleId || ""}`,
    `name=${ev.title}`,
  ]
    .filter(Boolean)
    .join("\t");
  return `LEEF:2.0|${PEPPER_DEVICE_VENDOR}|${PEPPER_DEVICE_PRODUCT}|${PEPPER_VERSION}|${
    ev.ruleId || "finding"
  }|\t|${attrs}`;
}

export function eventToJson(ev: SiemFindingEvent): string {
  return JSON.stringify({ source: "pepper", ...ev });
}

function isHttpsEndpoint(endpoint: string): boolean {
  return /^https?:\/\//i.test(endpoint);
}

function parseSyslog(endpoint: string): {
  protocol: "udp" | "tcp";
  host: string;
  port: number;
} {
  const m = endpoint.match(/^(udp|tcp):\/\/([^:]+):(\d+)$/i);
  if (m) {
    return {
      protocol: m[1].toLowerCase() as "udp" | "tcp",
      host: m[2],
      port: parseInt(m[3], 10),
    };
  }
  const m2 = endpoint.match(/^([^:]+):(\d+)$/);
  if (m2) {
    return { protocol: "udp", host: m2[1], port: parseInt(m2[2], 10) };
  }
  throw new Error(`Invalid SIEM endpoint: ${endpoint}`);
}

async function sendUdp(host: string, port: number, line: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const sock = dgram.createSocket("udp4");
    sock.send(Buffer.from(line), port, host, (err) => {
      sock.close();
      if (err) reject(err);
      else resolve();
    });
  });
}

async function sendTcp(host: string, port: number, line: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const sock = net.createConnection({ host, port }, () => {
      sock.write(line + "\n", (err) => {
        sock.end();
        if (err) reject(err);
        else resolve();
      });
    });
    sock.on("error", reject);
    sock.setTimeout(5000, () => {
      sock.destroy();
      reject(new Error("SIEM TCP timeout"));
    });
  });
}

export function formatEvent(
  ev: SiemFindingEvent,
  format: SiemConfig["format"],
): string {
  if (format === "cef") return eventToCef(ev);
  if (format === "leef") return eventToLeef(ev);
  return eventToJson(ev);
}

export async function forwardToSiem(
  config: SiemConfig,
  events: SiemFindingEvent[],
): Promise<void> {
  if (events.length === 0) return;

  if (isHttpsEndpoint(config.endpoint)) {
    const lines = events.map((e) => formatEvent(e, config.format)).join("\n");
    const headers: Record<string, string> = {
      "Content-Type": config.format === "json" ? "application/json" : "text/plain",
    };
    if (config.apiKey) headers["Authorization"] = `Bearer ${config.apiKey}`;
    const res = await fetch(config.endpoint, {
      method: "POST",
      headers,
      body:
        config.format === "json"
          ? JSON.stringify(events.map((e) => ({ source: "pepper", ...e })))
          : lines,
    });
    if (!res.ok) {
      throw new Error(`SIEM HTTPS forward failed (${res.status})`);
    }
    return;
  }

  const target = parseSyslog(config.endpoint);
  for (const ev of events) {
    const line = formatEvent(ev, config.format);
    if (target.protocol === "udp") {
      await sendUdp(target.host, target.port, line);
    } else {
      await sendTcp(target.host, target.port, line);
    }
  }
}
