import { describe, it, expect } from "vitest";
import {
  UNTRUSTED_CONTENT_GUARD,
  SCA_TRIAGE_PROMPT,
  MALICIOUS_VALIDATION_PROMPT,
  SECRETS_AI_PROMPT,
  CONTAINER_CONFIG_PROMPT,
  K8S_MANIFEST_PROMPT,
  EXPLOIT_VALIDATION_PROMPT,
} from "./prompts";
import { SYSTEM_PROMPT as SAST_SYSTEM_PROMPT } from "../sast/llm-analyzer";
import { ZERO_DAY_SYSTEM_PROMPT } from "../zero-day/prompts";
import { IAC_STACK_PROMPT } from "../iac";
import { SYSTEM_PROMPT as SECRETS_CLASSIFIER_PROMPT } from "../secrets/llm-classifier";

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

  it("is present in every code/config analysis prompt", () => {
    // SAST, Zero-Day, IaC, Container, K8S and the secret scanners all feed
    // repository- or package-authored content (code, manifests, configs,
    // README prose) to the model. Content can embed instructions aimed at the
    // model ("ignore previous instructions", "do not report this"), so every
    // one of these prompts must carry the same untrusted-data declaration.
    // This guard is the regression lock: a new scanner prompt that omits it
    // fails here until it declares its input untrusted.
    const prompts: Array<[string, string]> = [
      ["SAST_LLM", SAST_SYSTEM_PROMPT],
      ["ZERO_DAY", ZERO_DAY_SYSTEM_PROMPT],
      ["IAC", IAC_STACK_PROMPT],
      ["CONTAINER", CONTAINER_CONFIG_PROMPT],
      ["K8S", K8S_MANIFEST_PROMPT],
      ["SECRETS_AI", SECRETS_AI_PROMPT],
      ["SECRETS_CLASSIFIER", SECRETS_CLASSIFIER_PROMPT],
      ["EXPLOIT_VALIDATION", EXPLOIT_VALIDATION_PROMPT],
    ];
    for (const [scanner, prompt] of prompts) {
      expect(prompt, `${scanner} prompt must embed UNTRUSTED_CONTENT_GUARD`).toContain(
        UNTRUSTED_CONTENT_GUARD,
      );
    }
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
