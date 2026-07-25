import { describe, it, expect } from "vitest";
import {
  UNTRUSTED_CONTENT_GUARD,
  SCA_TRIAGE_PROMPT,
  MALICIOUS_VALIDATION_PROMPT,
} from "./prompts";

/**
 * In supply-chain analysis the adversary authors the input (install scripts,
 * package metadata, lockfile version strings). A successful prompt injection
 * yields a false negative — malware waved through — so every prompt that
 * receives package-authored content must carry the guard.
 */
describe("untrusted content guard", () => {
  // Phrases are matched whitespace-tolerantly so that re-wrapping the prompt
  // text does not fail these assertions.
  it("tells the model that supplied content is data, never instructions", () => {
    expect(UNTRUSTED_CONTENT_GUARD).toMatch(/NEVER\s+instructions/i);
    expect(UNTRUSTED_CONTENT_GUARD).toMatch(/ignore\s+previous\s+instructions/i);
    expect(UNTRUSTED_CONTENT_GUARD).toMatch(
      /judge\s+only\s+from\s+the\s+technical\s+evidence/i,
    );
  });

  it("treats attempted manipulation as a malicious signal rather than complying", () => {
    expect(UNTRUSTED_CONTENT_GUARD).toMatch(/malicious\s+signal/i);
  });

  it("is present in every prompt that receives package-authored content", () => {
    expect(SCA_TRIAGE_PROMPT).toContain(UNTRUSTED_CONTENT_GUARD);
    expect(MALICIOUS_VALIDATION_PROMPT).toContain(UNTRUSTED_CONTENT_GUARD);
  });
});

describe("SCA triage prompt", () => {
  it("forbids judging from recalled CVE knowledge", () => {
    // Regression: the payload used to omit advisory text entirely, so the model
    // had to infer exploit preconditions from the CVE ID alone.
    expect(SCA_TRIAGE_PROMPT).toMatch(/do NOT use recalled knowledge/i);
    expect(SCA_TRIAGE_PROMPT).toMatch(/not specified in advisory/i);
  });

  it("requires KEV-listed vulnerabilities to be kept", () => {
    expect(SCA_TRIAGE_PROMPT).toMatch(/cisaKevListed=true.*keep=true/i);
  });

  it("states that absent EPSS/KEV data is not low risk", () => {
    expect(SCA_TRIAGE_PROMPT).toMatch(/mean "no data", not "low risk"/i);
  });

  it("forbids guessing fix versions", () => {
    expect(SCA_TRIAGE_PROMPT).toMatch(/Never guess a version number/i);
  });
});
