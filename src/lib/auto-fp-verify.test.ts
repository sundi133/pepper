import { beforeEach, describe, expect, it, vi } from "vitest";

const { findMany, updateMany, analyzeWithLlm } = vi.hoisted(() => ({
  findMany: vi.fn(),
  updateMany: vi.fn(),
  analyzeWithLlm: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({ prisma: { finding: { findMany, updateMany } } }));
vi.mock("@/lib/llm-gateway", () => ({
  createLlmClient: vi.fn(() => ({})),
  analyzeWithLlm,
  parseLlmJsonResponse: (raw: string, fallback: unknown) => {
    try {
      return JSON.parse(raw);
    } catch {
      return fallback;
    }
  },
}));
vi.mock("@/lib/suppression-rules", () => ({ buildFpExamplesForPrompt: vi.fn(async () => "") }));

import { autoVerifyFalsePositives } from "./auto-fp-verify";

const orgSettings = {
  llmProvider: "openai",
  llmBaseUrl: "https://api.openai.com/v1",
  llmModel: "gpt-4o-mini",
  llmApiKey: "sk-test",
  enableLlmSast: true,
  enableLlmSecrets: true,
  osvApiUrl: "",
  vulnDbMode: "online" as const,
  orgId: "o1",
};
const log = { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() } as never;

function finding(id: string, ruleId: string | null) {
  return { id, scanner: "SAST_LLM", severity: "HIGH", title: id, description: "", filePath: "a", startLine: 1, snippet: "", ruleId, cweId: null };
}

beforeEach(() => {
  vi.clearAllMocks();
  analyzeWithLlm.mockResolvedValue(JSON.stringify({ classifications: [] }));
});

describe("autoVerifyFalsePositives", () => {
  it("leaves mobile app review findings alone and still checks findings without a ruleId", async () => {
    findMany.mockResolvedValue([
      finding("astra", "ai-mobile-review/exported-provider"),
      finding("no-rule", null),
      finding("pattern", "java.lang.security.sqli"),
    ]);

    const result = await autoVerifyFalsePositives("s1", orgSettings, log);

    expect(result.analyzed).toBe(2);
    const sent = JSON.parse(analyzeWithLlm.mock.calls[0][3] as string) as { findings: Array<{ title: string }> };
    expect(sent.findings.map((f) => f.title)).toEqual(["no-rule", "pattern"]);
  });

  it("does nothing when only mobile app review findings exist", async () => {
    findMany.mockResolvedValue([finding("astra", "ai-mobile-review/hardcoded-key")]);
    const result = await autoVerifyFalsePositives("s1", orgSettings, log);
    expect(result).toEqual({ analyzed: 0, marked: 0 });
    expect(analyzeWithLlm).not.toHaveBeenCalled();
  });
});
