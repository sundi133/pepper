import { describe, expect, it } from "vitest";
import { applyQualityGates } from "./quality-gates";
import type { RawFinding } from "../types";

const f = (over: Partial<RawFinding>): RawFinding => ({
  scanner: "SAST_LLM",
  severity: "HIGH",
  title: "Destructive database reset with no authorization check",
  description: "populate_db drops every table",
  filePath: "api_views/main.py",
  startLine: 6,
  cweId: "CWE-862",
  confidence: 0.72,
  metadata: { validation: "unconfirmed" },
  ...over,
});

describe("quality gates and unjudged authorization / logic findings", () => {
  it("keeps an unconfirmed authorization finding above the first-pass floor, even without a written fix", () => {
    expect(applyQualityGates([f({})])).toHaveLength(1);
  });

  it("still applies the normal floor to unconfirmed findings of other kinds", () => {
    expect(applyQualityGates([f({ title: "No password strength constraints", cweId: "CWE-521" })])).toHaveLength(0);
  });

  it("still drops an authorization finding below the first-pass floor", () => {
    expect(applyQualityGates([f({ confidence: 0.6 })])).toHaveLength(0);
  });

  it("does not relax anything for findings the validator did judge", () => {
    expect(applyQualityGates([f({ metadata: {} })])).toHaveLength(0);
  });
});

// Agent "deep scan" findings (src/scanners/mobile-agent) are emitted as
// scanner:"SAST_LLM" but review a decompiled binary (.ipa/.apk), so they carry
// no startLine and map confidence high→0.9, medium→0.6, low→0.3. Reproduces the
// DVIA-v2.ipa regression where all ~23 agent findings were silently dropped.
const agentFinding = (over: Partial<RawFinding>): RawFinding => ({
  scanner: "SAST_LLM",
  severity: "HIGH",
  title: "Hardcoded encryption key in binary",
  description: "AES key recovered from the compiled app",
  filePath: "DVIA-v2.ipa!/strings: crypto",
  startLine: undefined,
  confidence: 0.9,
  metadata: { scanner: "agent-scan" },
  ...over,
});

describe("quality gates and agent deep-scan (binary) findings", () => {
  it("keeps HIGH (0.9) and MEDIUM (0.6) agent findings and drops the INFO one", () => {
    const kept = applyQualityGates([
      agentFinding({ severity: "HIGH", confidence: 0.9 }),
      agentFinding({
        severity: "MEDIUM",
        confidence: 0.6,
        title: "Insecure data storage in plist",
        filePath: "DVIA-v2.ipa!/Info.plist",
      }),
      agentFinding({
        severity: "INFO",
        confidence: 0.3,
        title: "Unparsed model output",
      }),
    ]);
    expect(kept).toHaveLength(2);
    expect(kept.map((x) => x.severity).sort()).toEqual(["HIGH", "MEDIUM"]);
  });

  it("keeps a LOW-confidence (0.3) agent finding — the mobile/agent path has NO confidence floor", () => {
    // The sandboxed binary review has no source for a second validation pass, so
    // every finding it reports is surfaced (matching the standalone agent's
    // recall); dedup + the other gates + the reviewer judge. Source SAST keeps 0.75.
    expect(
      applyQualityGates([agentFinding({ severity: "LOW", confidence: 0.3 })]),
    ).toHaveLength(1);
  });

  it("keeps an agent finding with no line number and no written fix", () => {
    expect(
      applyQualityGates([
        agentFinding({ startLine: undefined, metadata: { scanner: "agent-scan" } }),
      ]),
    ).toHaveLength(1);
  });

  it("carve-out does NOT leak: a normal source SAST_LLM finding with no line is still dropped", () => {
    expect(
      applyQualityGates([
        {
          scanner: "SAST_LLM",
          severity: "HIGH",
          title: "SQL injection in user lookup",
          description: "Fix: use parameterized queries",
          filePath: "api_views/main.py",
          startLine: undefined,
          cweId: "CWE-89",
          confidence: 0.9,
        },
      ]),
    ).toHaveLength(0);
  });

  it("carve-out does NOT leak: a normal source SAST_LLM finding at 0.6 is still below the 0.75 floor", () => {
    expect(
      applyQualityGates([
        {
          scanner: "SAST_LLM",
          severity: "MEDIUM",
          title: "Weak hash usage",
          description: "Fix: use SHA-256",
          filePath: "api_views/main.py",
          startLine: 42,
          cweId: "CWE-328",
          confidence: 0.6,
        },
      ]),
    ).toHaveLength(0);
  });
});
