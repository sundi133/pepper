import { describe, it, expect } from "vitest";
import {
  eventToCef,
  eventToLeef,
  eventToJson,
  formatEvent,
  type SiemFindingEvent,
} from "./siem";

const ev: SiemFindingEvent = {
  scanId: "scan_1",
  organizationId: "org_1",
  projectName: "demo",
  severity: "HIGH",
  title: "SQL Injection in user controller",
  ruleId: "SAST-SQLI-001",
  cveId: null,
  cweId: "CWE-89",
  filePath: "src/users.ts",
  line: 42,
  scanner: "SAST_LLM",
  detectedAt: "2026-05-17T10:00:00.000Z",
};

describe("siem formatters", () => {
  it("emits CEF with vendor/product header and extension key=value", () => {
    const cef = eventToCef(ev);
    expect(cef.startsWith("CEF:0|Pepper|Pepper-SAST|1.0|SAST-SQLI-001|")).toBe(
      true,
    );
    expect(cef).toContain("cs5Label=cwe cs5=CWE-89");
    expect(cef).toContain("fname=src/users.ts");
  });

  it("emits LEEF 2.0 with tab-delimited attributes", () => {
    const leef = eventToLeef(ev);
    expect(leef.startsWith("LEEF:2.0|Pepper|Pepper-SAST|1.0|")).toBe(true);
    expect(leef).toContain("\tcwe=CWE-89");
  });

  it("emits JSON for the json format", () => {
    const json = JSON.parse(eventToJson(ev));
    expect(json.source).toBe("pepper");
    expect(json.scanId).toBe("scan_1");
  });

  it("formatEvent dispatches by format", () => {
    expect(formatEvent(ev, "cef").startsWith("CEF:0")).toBe(true);
    expect(formatEvent(ev, "leef").startsWith("LEEF:2.0")).toBe(true);
    const j = JSON.parse(formatEvent(ev, "json"));
    expect(j.scanId).toBe("scan_1");
  });
});
