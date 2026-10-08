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
