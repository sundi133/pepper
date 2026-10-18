import { beforeEach, describe, expect, it, vi } from "vitest";
import { sampleData, stubSources } from "./test-fixtures";

// ─── Mocks for the job runner ─────────────────────────────────────────
const reportRow = vi.fn();
const updates: Array<Record<string, unknown>> = [];
const claim = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: {
    customReport: {
      findUnique: (...a: unknown[]) => reportRow(...a),
      updateMany: (...a: unknown[]) => claim(...a),
      update: vi.fn(async (args: { data: Record<string, unknown> }) => {
        updates.push(args.data);
        return {};
      }),
    },
    orgSettings: { findUnique: vi.fn(async () => null) },
  },
}));
const analyze = vi.fn();
vi.mock("@/lib/llm-gateway", async (orig) => ({
  ...(await orig<typeof import("@/lib/llm-gateway")>()),
  getLlmConfig: () => ({ provider: "openai", baseUrl: "https://api.openai.com/v1", apiKey: "sk-test", model: "gpt-test" }),
  createLlmClient: () => ({ type: "openai", client: {}, model: "gpt-test" }),
  analyzeWithLlm: (...a: unknown[]) => analyze(...a),
}));
const preflight = vi.fn();
vi.mock("@/lib/llm-preflight", () => ({ checkLlmAvailable: (...a: unknown[]) => preflight(...a) }));
vi.mock("./sources", () => ({
  loadReportData: vi.fn(async () => sampleData()),
  createReportSources: vi.fn(() => stubSources()),
}));
const audit = vi.fn();
vi.mock("@/lib/audit-log", () => ({ writeAuditLog: (...a: unknown[]) => audit(...a) }));

import { generateCustomReport, parseSectionReply, runCustomReport, sanitizeToolCalls, type LlmCall } from "./agent";

const TEMPLATE = {
  name: "Monthly status",
  format: "markdown",
  body: "# Status for {{scan.repository}}\n\n## Summary\nOverall risk in two sentences. Critical: {{findings.critical_count}}.\n\n## Top risks\nOne bullet per risk.",
  instructions: "Audience: CTO.",
};

/** A scripted model: answers by stage, records what it was asked. */
function scriptedLlm(sectionAnswers: Record<string, string[]>): LlmCall & { prompts: string[] } {
  const prompts: string[] = [];
  const queues = Object.fromEntries(Object.entries(sectionAnswers).map(([k, v]) => [k, [...v]]));
  const fn = (async (system: string, user: string) => {
    prompts.push(user);
    if (system.startsWith("You plan")) {
      return JSON.stringify({
        sections: [
          { index: 0, toolCalls: [{ tool: "get_scan_summary", args: {} }] },
          { index: 1, toolCalls: [{ tool: "list_findings", args: { severity: ["CRITICAL", "HIGH"], limit: 5 } }, { tool: "rm_rf", args: {} }] },
        ],
      });
    }
    const section = user.match(/^SECTION: (.*)$/m)?.[1] ?? "";
    return queues[section]?.shift() ?? "{}";
  }) as unknown as LlmCall & { prompts: string[] };
  fn.prompts = prompts;
  return fn;
}

describe("generateCustomReport (agent pipeline)", () => {
  it("plans, writes each section from tool data, fills placeholders and grounds citations", async () => {
    const llm = scriptedLlm({
      Summary: [JSON.stringify({ markdown: "Risk is high: 1 critical issue [F1]." })],
      "Top risks": [
        JSON.stringify({ toolCalls: [{ tool: "get_finding", args: { refs: ["F1"] } }] }),
        JSON.stringify({ markdown: "- SQL injection [F1]\n- Invented RCE [F99]\n- XSS [F2]" }),
      ],
    });
    const progress: number[] = [];
    const out = await generateCustomReport({
      data: sampleData(),
      sources: stubSources(),
      template: TEMPLATE,
      extraInstructions: "Mention the payment flow.",
      llm,
      now: new Date("2026-10-16T12:00:00Z"),
      onProgress: (p) => {
        if (p >= 0) progress.push(p);
      },
    });

    expect(out.title).toBe("Status for payments");
    expect(out.markdown).toContain("## Summary\n\nRisk is high: 1 critical issue [F1].");
    expect(out.markdown).toContain("- SQL injection [F1]\n- XSS [F2]");
    expect(out.markdown).not.toContain("F99");
    expect(out.markdown).not.toContain("Invented RCE");
    expect(out.grounding.removed).toEqual(["F99"]);
    expect(out.markdown).toContain("## Referenced findings");
    // Plan + Summary + Top risks (two rounds: a data request, then the answer).
    expect(out.llmCalls).toBe(4);
    // Placeholder values reached the model already filled; instructions too.
    const summaryPrompt = llm.prompts.find((p) => p.includes("SECTION: Summary"))!;
    expect(summaryPrompt).toContain("Critical: 1.");
    expect(summaryPrompt).toContain("Audience: CTO.");
    expect(summaryPrompt).toContain("Mention the payment flow.");
    // The section only received the data its plan asked for (the unknown tool was dropped).
    const risksPrompt = llm.prompts.filter((p) => p.includes("SECTION: Top risks"));
    expect(risksPrompt[0]).toContain("### list_findings");
    expect(risksPrompt[0]).not.toContain("rm_rf");
    expect(risksPrompt[1]).toContain("### get_finding");
    expect(progress.at(-1)).toBe(92);
  });

  it("stops asking for data after the last round", async () => {
    const ask = JSON.stringify({ toolCalls: [{ tool: "aggregate_findings", args: { groupBy: "cwe" } }] });
    const llm = scriptedLlm({ Summary: [ask, ask, ask, ask], "Top risks": [JSON.stringify({ markdown: "ok" })] });
    const out = await generateCustomReport({ data: sampleData(), sources: stubSources(), template: TEMPLATE, extraInstructions: null, llm, now: new Date() });
    // 1 plan + 3 Summary rounds (bounded) + 1 Top risks.
    expect(out.llmCalls).toBe(5);
    expect(out.grounding.emptySections).toBe(1);
    expect(out.markdown).toContain("could not be generated");
  });

  it("fails when the model returns nothing usable for any section", async () => {
    const llm: LlmCall = async () => "{}";
    await expect(
      generateCustomReport({ data: sampleData(), sources: stubSources(), template: TEMPLATE, extraInstructions: null, llm, now: new Date() }),
    ).rejects.toThrow(/no usable content/);
  });

  it("accepts a section written as plain Markdown or JSON inside prose (Claude without a JSON format)", async () => {
    const llm = scriptedLlm({
      Summary: ["Critical: 1\n\n- **Scan:** risk is high [F1]."],
      "Top risks": ['Here is the section:\n{"markdown":"- SQL injection [F1]"}'],
    });
    const out = await generateCustomReport({ data: sampleData(), sources: stubSources(), template: TEMPLATE, extraInstructions: null, llm, now: new Date() });
    expect(out.grounding.emptySections).toBe(0);
    expect(out.markdown).toContain("- **Scan:** risk is high [F1].");
    expect(out.markdown).toContain("- SQL injection [F1]");
    expect(out.markdown).not.toContain("Here is the section");
  });

  it("parses section replies", () => {
    expect(parseSectionReply('{"markdown":"x"}')).toEqual({ markdown: "x" });
    expect(parseSectionReply('```json\n{"toolCalls":[]}\n```')).toEqual({ toolCalls: [] });
    expect(parseSectionReply("```markdown\n### Top\n- a\n```")).toEqual({ markdown: "### Top\n- a" });
    expect(parseSectionReply("{}")).toEqual({});
    expect(parseSectionReply("")).toEqual({});
    expect(parseSectionReply('{"markdown": "cut off')).toEqual({});
  });

  it("only accepts known tools, bounded per round", () => {
    const calls = sanitizeToolCalls([
      { tool: "list_findings", args: { limit: 5 } },
      { tool: "exec_sql" },
      "nonsense",
      { tool: "get_scan_summary", args: [1] },
      { tool: "aggregate_findings" },
      { tool: "get_dependency_summary" },
      { tool: "compare_with_previous_scan" },
    ]);
    expect(calls.map((c) => c.tool)).toEqual(["list_findings", "get_scan_summary", "aggregate_findings", "get_dependency_summary"]);
    expect(calls[1].args).toEqual({});
  });
});

describe("runCustomReport (job lifecycle)", () => {
  const queued = {
    id: "r1",
    organizationId: "o1",
    scanId: "scan_1",
    createdBy: "u1",
    status: "QUEUED",
    templateName: "Monthly status",
    templateSnapshot: TEMPLATE,
    extraInstructions: null,
    scan: { id: "scan_1", project: { name: "payments" } },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    updates.length = 0;
    reportRow.mockResolvedValue(queued);
    claim.mockResolvedValue({ count: 1 });
    preflight.mockResolvedValue({ ok: true });
    analyze.mockImplementation(async (_c: unknown, _m: string, system: string, user: string) => {
      if (system.startsWith("You plan")) return JSON.stringify({ sections: [] });
      return user.includes("SECTION: Summary")
        ? JSON.stringify({ markdown: "Summary text [F1] and token ghp_abcdefghijklmnopqrstuvwxyz0123456789" })
        : JSON.stringify({ markdown: "Risks [F2]" });
    });
  });

  it("moves QUEUED → RUNNING → COMPLETED and stores sanitized output with the AI footer", async () => {
    await runCustomReport("r1");
    expect(claim).toHaveBeenCalledWith(expect.objectContaining({ where: { id: "r1", status: "QUEUED" }, data: expect.objectContaining({ status: "RUNNING" }) }));
    const final = updates.at(-1)!;
    expect(final.status).toBe("COMPLETED");
    expect(final.progress).toBe(100);
    expect(final.title).toBe("Status for payments");
    expect(final.html).toContain("generated by AI from Pepper scan scan_1");
    expect(final.html).toContain("with model gpt-test");
    expect(final.html).not.toMatch(/<script/i);
    // A secret the model echoed is masked in what gets stored.
    expect(final.markdown).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz0123456789");
    expect(final.markdown).toContain("[[SECRET_");
    // Progress was reported in between.
    expect(updates.some((u) => typeof u.stage === "string" && String(u.stage).startsWith("Writing sections"))).toBe(true);
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({ action: "report.custom_completed", resourceId: "r1" }));
  });

  it("fails with a clear message when the AI provider refuses (no credit / bad key)", async () => {
    preflight.mockResolvedValue({ ok: false, status: 402, reason: "the account has no credit left (402: insufficient credits)" });
    await runCustomReport("r1");
    const final = updates.at(-1)!;
    expect(final.status).toBe("FAILED");
    expect(String(final.errorMessage)).toMatch(/AI provider refused the request: openai would not run gpt-test because the account has no credit left/);
    expect(analyze).not.toHaveBeenCalled();
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({ action: "report.custom_failed" }));
  });

  it("fails when every model answer is empty (provider errors degrade to '{}')", async () => {
    analyze.mockResolvedValue("{}");
    await runCustomReport("r1");
    const final = updates.at(-1)!;
    expect(final.status).toBe("FAILED");
    expect(String(final.errorMessage)).toMatch(/no usable content/);
  });

  it("does nothing for a report that is not queued, or claimed by another worker", async () => {
    reportRow.mockResolvedValueOnce({ ...queued, status: "COMPLETED" });
    await runCustomReport("r1");
    expect(claim).not.toHaveBeenCalled();
    claim.mockResolvedValueOnce({ count: 0 });
    await runCustomReport("r1");
    expect(updates).toHaveLength(0);
    expect(analyze).not.toHaveBeenCalled();
  });
});
