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

import { triageScaFindings } from "./triage";

const ADVISORY =
  "Prototype pollution in the merge() function allows an attacker to inject " +
  "properties onto Object.prototype. Exploitation requires the application to " +
  "pass attacker-controlled JSON into merge(). Not exploitable when input is " +
  "validated against a schema first.";

function finding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    scanner: "SCA",
    severity: "HIGH",
    title: "CVE-2024-0001: prototype pollution",
    description: ADVISORY,
    ruleId: "GHSA-aaaa-bbbb-cccc",
    cveId: "CVE-2024-0001",
    cweId: "CWE-1321",
    confidence: 1.0,
    metadata: {
      packageName: "deepmerge",
      packageVersion: "1.0.0",
      ecosystem: "npm",
      fixVersion: "1.0.1",
      epssScore: 0.42,
      epssPercentile: 0.97,
      cisaKevListed: true,
      cisaKevRansomwareUse: "Known",
      supplyChainRisk: {
        directDependency: true,
        transitiveSeverity: "immediate",
      },
    },
    ...overrides,
  };
}

const cloudConfig = {
  provider: "openai",
  baseUrl: "https://api.openai.com",
  apiKey: "k",
  model: "gpt-test",
};

/** Parse the JSON payload handed to the LLM on a given call. */
function payloadFromCall(callIndex = 0) {
  const userContent = analyzeWithLlm.mock.calls[callIndex][3] as string;
  return JSON.parse(userContent) as {
    vulnerabilities: Array<Record<string, unknown>>;
  };
}

beforeEach(() => {
  analyzeWithLlm.mockReset();
  analyzeWithLlm.mockResolvedValue(
    JSON.stringify({
      triaged: [
        {
          osvId: "GHSA-aaaa-bbbb-cccc",
          keep: true,
          reason: "reachable and exploited in the wild",
          metadata: { reachable: true, exploitPreconditions: "attacker JSON" },
        },
      ],
    }),
  );
});

describe("SCA triage evidence payload", () => {
  it("sends the advisory text so the model does not judge from the CVE ID alone", async () => {
    await triageScaFindings([finding()], cloudConfig);

    const vuln = payloadFromCall().vulnerabilities[0];
    expect(vuln.advisory).toContain("Prototype pollution");
    expect(vuln.advisory).toContain("attacker-controlled JSON");
  });

  it("sends EPSS and CISA KEV exploitation signals", async () => {
    await triageScaFindings([finding()], cloudConfig);

    const vuln = payloadFromCall().vulnerabilities[0];
    expect(vuln.epssScore).toBe(0.42);
    expect(vuln.cisaKevListed).toBe(true);
    expect(vuln.cisaKevRansomwareUse).toBe("Known");
  });

  it("sends dependency directness and CWE alongside the advisory", async () => {
    await triageScaFindings([finding()], cloudConfig);

    const vuln = payloadFromCall().vulnerabilities[0];
    expect(vuln.directDependency).toBe(true);
    expect(vuln.transitiveSeverity).toBe("immediate");
    expect(vuln.cweId).toBe("CWE-1321");
    expect(vuln.fixVersion).toBe("1.0.1");
  });

  it("marks the advisory as unavailable rather than omitting the field", async () => {
    await triageScaFindings([finding({ description: "" })], cloudConfig);

    const vuln = payloadFromCall().vulnerabilities[0];
    expect(vuln.advisory).toBe("no advisory text available");
  });

  it("truncates long advisories and flags the truncation", async () => {
    const long = "word ".repeat(2000);
    await triageScaFindings([finding({ description: long })], cloudConfig);

    const vuln = payloadFromCall().vulnerabilities[0] as { advisory: string };
    expect(vuln.advisory).toContain("[truncated]");
    // Cloud budget is 1500 chars plus the truncation marker.
    expect(vuln.advisory.length).toBeLessThan(1600);
  });

  it("uses a smaller advisory budget and batch size for local Ollama models", async () => {
    const long = "word ".repeat(2000);
    const findings = Array.from({ length: 10 }, (_, i) =>
      finding({
        description: long,
        ruleId: `GHSA-${i}`,
        metadata: {
          packageName: `pkg-${i}`,
          packageVersion: "1.0.0",
          ecosystem: "npm",
        },
      }),
    );

    await triageScaFindings(findings, { ...cloudConfig, provider: "ollama" });

    // Ollama batch size is 8, so 10 findings require 2 requests.
    expect(analyzeWithLlm).toHaveBeenCalledTimes(2);
    const vuln = payloadFromCall().vulnerabilities[0] as { advisory: string };
    expect(vuln.advisory.length).toBeLessThan(600);
  });

  it("keeps findings when the LLM call fails", async () => {
    analyzeWithLlm.mockRejectedValue(new Error("model unavailable"));

    const result = await triageScaFindings([finding()], cloudConfig);

    expect(result).toHaveLength(1);
    expect(result[0].cveId).toBe("CVE-2024-0001");
  });

  it("drops findings the model marks keep=false", async () => {
    analyzeWithLlm.mockResolvedValue(
      JSON.stringify({
        triaged: [
          {
            osvId: "GHSA-aaaa-bbbb-cccc",
            keep: false,
            reason: "package not imported in source",
          },
        ],
      }),
    );

    const result = await triageScaFindings([finding()], cloudConfig);
    expect(result).toHaveLength(0);
  });

  it("returns an empty list without calling the model for no findings", async () => {
    const result = await triageScaFindings([], cloudConfig);
    expect(result).toEqual([]);
    expect(analyzeWithLlm).not.toHaveBeenCalled();
  });

  it("preserves the advisory excerpt the verdict was based on", async () => {
    // enrichFinding() rewrites `description`, so the evidence behind a keep/drop
    // decision must survive in metadata for auditing.
    const result = await triageScaFindings([finding()], cloudConfig);

    expect(result[0].metadata?.advisoryExcerpt).toContain("Prototype pollution");
    expect(result[0].metadata?.triagedByLlm).toBe(true);
    expect(result[0].description).not.toContain("Prototype pollution");
  });

  it("instructs the model to treat advisory text as untrusted data", async () => {
    await triageScaFindings([finding()], cloudConfig);

    const systemPrompt = analyzeWithLlm.mock.calls[0][2] as string;
    expect(systemPrompt).toContain("UNTRUSTED CONTENT");
    expect(systemPrompt).toMatch(/never instructions|NEVER instructions/i);
  });
});
