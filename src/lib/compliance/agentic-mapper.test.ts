import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock only the network-facing gateway functions; keep parseLlmJsonResponse real.
vi.mock("@/lib/llm-gateway", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/llm-gateway")>();
  return {
    ...actual,
    createLlmClient: vi.fn(() => ({ type: "openai" })),
    analyzeWithLlm: vi.fn(),
  };
});

import { analyzeWithLlm } from "@/lib/llm-gateway";
import { mapFindingsAgentic } from "./agentic-mapper";
import { ComplianceFramework } from "./pdf-parser";
import type { FindingForMapping } from "./llm-mapper";

const fx: ComplianceFramework = {
  name: "Test FW",
  version: "1.0",
  fileName: "t.json",
  controlCatalog: "",
  controls: [
    {
      controlId: "C-INJ", chunkId: "1", type: "t", theme: "Tech", title: "Injection",
      summary: "", implementationChecklist: [], evidenceExamples: [],
      coverage: "assessable", cweMapping: ["CWE-89"],
    },
    {
      controlId: "C-SUPPORT", chunkId: "2", type: "t", theme: "Tech", title: "Support",
      summary: "", implementationChecklist: [], evidenceExamples: [],
      coverage: "assessable", appliesTo: { scanners: ["SAST_LLM"] },
    },
    {
      controlId: "C-POLICY", chunkId: "3", type: "t", theme: "Org", title: "Policy",
      summary: "", implementationChecklist: [], evidenceExamples: [],
      coverage: "not-assessable",
    },
  ],
};

const finding = (o: Partial<FindingForMapping>): FindingForMapping => ({
  id: "f", title: "t", description: "d", severity: "HIGH",
  scanner: "SAST_LLM", cweId: null, ruleId: null, filePath: null, ...o,
});

const mockLlm = vi.mocked(analyzeWithLlm);

beforeEach(() => mockLlm.mockReset());

// Route reason vs verify by inspecting the system prompt.
function wire(reasonJson: unknown, verifyJson: unknown) {
  mockLlm.mockImplementation(async (_c, _m, system: string) =>
    /skeptical/i.test(system)
      ? JSON.stringify(verifyJson)
      : JSON.stringify(reasonJson),
  );
}

describe("mapFindingsAgentic", () => {
  it("gates to grounded findings, verifies, and validates against the catalog", async () => {
    // reason proposes: a good control, a verify-rejected control, and a hallucinated id
    wire(
      {
        mappings: [
          {
            findingId: "f1",
            controls: [
              { controlId: "C-INJ", relevance: "direct", reasoning: "sqli", confidence: 0.9 },
              { controlId: "C-SUPPORT", relevance: "supporting", reasoning: "weak", confidence: 0.6 },
              { controlId: "C-HALLUCINATION", relevance: "direct", reasoning: "nope", confidence: 0.5 },
            ],
          },
        ],
      },
      {
        verdicts: [
          { index: 0, verdict: "uphold", confidence: 0.95, note: "clear" },
          { index: 1, verdict: "reject", note: "not applicable" },
          { index: 2, verdict: "uphold", confidence: 0.5 }, // upheld but not in catalog
        ],
      },
    );

    const findings = [
      finding({ id: "f1", cweId: "CWE-89", scanner: "SAST_LLM" }), // grounded
      finding({ id: "f2", cweId: "CWE-999", scanner: "CONTAINER" }), // no prior → gated out
    ];

    const results = await mapFindingsAgentic(findings, fx, {
      provider: "openai", baseUrl: "x", apiKey: "k", model: "m",
    });

    const f1 = results.find((r) => r.findingId === "f1")!;
    const f2 = results.find((r) => r.findingId === "f2")!;

    // C-SUPPORT rejected by verify; C-HALLUCINATION dropped by catalog validation.
    expect(f1.controls.map((c) => c.controlId)).toEqual(["C-INJ"]);
    const inj = f1.controls[0];
    expect(inj.verified).toBe(true);
    expect(inj.confidence).toBeCloseTo(0.95);

    // f2 had no grounded prior → maps to nothing, no LLM call spent on it.
    expect(f2.controls).toEqual([]);

    // Exactly one reason + one verify call (single batch), not per-finding.
    expect(mockLlm).toHaveBeenCalledTimes(2);
  });

  it("degrades gracefully when the LLM returns unparseable output", async () => {
    // Reason returns junk → no mappings parsed → verify has nothing to review.
    mockLlm.mockResolvedValue("not json at all");
    const findings = [finding({ id: "f1", cweId: "CWE-89", scanner: "SAST_LLM" })];
    const results = await mapFindingsAgentic(findings, fx, {
      provider: "openai", baseUrl: "x", apiKey: "k", model: "m",
    });
    // No crash; the finding simply produces no controls this run.
    expect(results).toHaveLength(1);
    expect(results[0].findingId).toBe("f1");
    expect(Array.isArray(results[0].controls)).toBe(true);
  });
});
