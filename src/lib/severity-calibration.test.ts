import { describe, expect, it } from "vitest";
import {
  applySeverityCalibration,
  calibrateSeverity,
  parseSeverity,
} from "./severity-calibration";

describe("severity-calibration", () => {
  it("parses severity labels", () => {
    expect(parseSeverity("critical")).toBe("CRITICAL");
    expect(parseSeverity("High")).toBe("HIGH");
    expect(parseSeverity("unknown")).toBe("MEDIUM");
  });

  it("maps CWE-798 hardcoded secret to CRITICAL", () => {
    const r = calibrateSeverity({
      llmSeverity: "HIGH",
      cweId: "CWE-798",
      title: "Hardcoded Secret",
      confidence: 0.9,
      weaknessClass: "Hardcoded Credential",
    });
    expect(r.severity).toBe("CRITICAL");
    expect(r.adjusted).toBe(true);
  });

  it("downgrades injection without route context from model CRITICAL", () => {
    const r = calibrateSeverity({
      llmSeverity: "CRITICAL",
      cweId: "CWE-78",
      title: "Possible command injection",
      confidence: 0.72,
      weaknessClass: "Command Injection",
      metadata: { route: null, parameter: null },
    });
    expect(r.severity).not.toBe("CRITICAL");
    expect(["HIGH", "MEDIUM"]).toContain(r.severity);
  });

  it("caps misconfiguration at MEDIUM", () => {
    const r = calibrateSeverity({
      llmSeverity: "CRITICAL",
      title: "Missing security header",
      confidence: 0.85,
      weaknessClass: "Security Misconfiguration",
    });
    expect(r.severity).toBe("MEDIUM");
  });

  it("applySeverityCalibration writes metadata", () => {
    const f = applySeverityCalibration({
      scanner: "SAST_LLM",
      severity: "CRITICAL",
      title: "Hardcoded JWT secret",
      description: "x",
      cweId: "CWE-798",
      confidence: 0.88,
      metadata: {},
    });
    expect(f.severity).toBe("CRITICAL");
    expect(f.metadata?.weaknessClass).toBe("Hardcoded Credential");
    expect(f.metadata?.severityJustification).toContain("CRITICAL");
  });
});
