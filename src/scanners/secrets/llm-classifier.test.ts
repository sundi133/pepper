import { describe, it, expect, vi, beforeEach } from "vitest";
import type { RawFinding } from "../types";

const analyzeWithLlm = vi.fn();

vi.mock("@/lib/llm-gateway", () => ({
  createLlmClient: vi.fn(() => ({ type: "openai", client: {}, model: "test" })),
  analyzeWithLlm: (...args: unknown[]) => analyzeWithLlm(...args),
  parseLlmJsonResponse: (raw: string, fallback: unknown) => {
    try {
      return JSON.parse(raw);
    } catch {
      return fallback;
    }
  },
}));

import { classifySecrets } from "./llm-classifier";

function candidate(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    scanner: "SECRETS_LLM",
    severity: "CRITICAL",
    title: "AWS_ACCESS_KEY: Exposed secret",
    description: "",
    filePath: "src/aws.ts",
    startLine: 12,
    endLine: 12,
    snippet: "12: [MASKED AWS_ACCESS_KEY]",
    ruleId: "SECRET-AWS_ACCESS_KEY",
    cweId: "CWE-798",
    confidence: 0.8,
    masked: true,
    metadata: {
      credentialType: "AWS_ACCESS_KEY",
      maskedValue: "AKIA****",
      category: "Secret",
      weaknessClass: "Hardcoded Credential",
      evidence: "AKIA key in prod client",
      confidenceReason: "AKIA key in prod client",
    },
    ...overrides,
  };
}

const cloudConfig = {
  provider: "openai",
  baseUrl: "https://api.example.com",
  apiKey: "k",
  model: "gpt-test",
};

beforeEach(() => {
  analyzeWithLlm.mockReset();
});

describe("classifySecrets reasoning propagation", () => {
  it("keeps classified-true findings and drops confirmed false positives", async () => {
    analyzeWithLlm.mockResolvedValue(
      JSON.stringify({
        classifications: [
          { index: 0, isSecret: true, confidence: 0.97, reasoning: "live key in prod client" },
          { index: 1, isSecret: false, confidence: 0.9, reasoning: "test fixture" },
        ],
      }),
    );

    const kept = await classifySecrets(
      [candidate({ title: "AWS_ACCESS_KEY: a" }), candidate({ title: "AWS_ACCESS_KEY: b" })],
      cloudConfig,
    );

    expect(kept).toHaveLength(1);
    expect(kept[0].title).toBe("AWS_ACCESS_KEY: a");
  });

  it("raises confidence to the classifier's and records the reasoning", async () => {
    analyzeWithLlm.mockResolvedValue(
      JSON.stringify({
        classifications: [
          { index: 0, isSecret: true, confidence: 0.99, reasoning: "context shows real usage" },
        ],
      }),
    );

    const [kept] = await classifySecrets([candidate({ confidence: 0.8 })], cloudConfig);

    expect(kept.confidence).toBe(0.99);
    const meta = kept.metadata as Record<string, unknown>;
    expect(meta.classifierConfidence).toBe(0.99);
    expect(meta.classifierReasoning).toBe("context shows real usage");
    // The finding's confidenceReason keeps the pattern evidence AND appends the
    // second opinion, so downstream triage sees why this value survived.
    expect(meta.confidenceReason).toContain("classifier: context shows real usage");
    expect(meta.confidenceReason).toContain("AKIA key in prod client");
  });

  it("never lowers confidence below the finding when the classifier is less certain", async () => {
    analyzeWithLlm.mockResolvedValue(
      JSON.stringify({
        classifications: [{ index: 0, isSecret: true, confidence: 0.75 }],
      }),
    );

    const [kept] = await classifySecrets([candidate({ confidence: 0.92 })], cloudConfig);

    expect(kept.confidence).toBe(0.92);
    expect((kept.metadata as Record<string, unknown>).classifierConfidence).toBe(0.75);
  });

  it("keeps findings the model did not classify, unchanged", async () => {
    analyzeWithLlm.mockResolvedValue(JSON.stringify({ classifications: [] }));

    const [kept] = await classifySecrets(
      [candidate({ title: "keep-me", confidence: 0.81 })],
      cloudConfig,
    );

    expect(kept.title).toBe("keep-me");
    expect(kept.confidence).toBe(0.81);
    expect(kept.metadata).not.toHaveProperty("classifierConfidence");
  });

  it("fails closed (empty) on an LLM error, but never drops via a hunch", async () => {
    analyzeWithLlm.mockRejectedValue(new Error("boom"));

    const kept = await classifySecrets([candidate()], cloudConfig);

    expect(kept).toEqual([]);
  });
});