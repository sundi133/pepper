import { beforeEach, describe, expect, it, vi } from "vitest";

const analyze = vi.fn();
vi.mock("@/lib/llm-gateway", async (orig) => ({
  ...(await orig<typeof import("@/lib/llm-gateway")>()),
  analyzeWithLlm: (...a: unknown[]) => analyze(...a),
}));

import { validateCandidatesPass2 } from "./llm-analyzer";
import type { RawFinding } from "../types";

const candidate = (title: string, startLine: number): RawFinding => ({
  scanner: "SAST_LLM",
  severity: "HIGH",
  title,
  description: "",
  filePath: "api_views/books.py",
  startLine,
  endLine: startLine,
  cweId: "CWE-862",
  confidence: 0.7,
  metadata: { passPhase: 1 },
});
const A = candidate("Missing authentication on get_all_books", 12);
const B = candidate("Unauthenticated database reset in populate_db", 40);
const injection = (title: string, startLine: number): RawFinding => ({ ...candidate(title, startLine), cweId: "CWE-89" });
const confirm = (c: RawFinding) => ({ title: c.title, severity: "HIGH", description: "confirmed", filePath: c.filePath, startLine: c.startLine, cweId: c.cweId, confidence: 0.85, metadata: {} });
const run = () => validateCandidatesPass2({} as never, "m", [A, B], "", 8192);

beforeEach(() => analyze.mockReset());

describe("second validation pass", () => {
  it("drops an injection candidate a complete answer leaves out (rejected)", async () => {
    const S = injection("SQL injection via search term", 30);
    analyze.mockResolvedValue(JSON.stringify({ findings: [confirm(A)] }));
    const out = await validateCandidatesPass2({} as never, "m", [A, S], "", 8192);
    expect(out.map((f) => f.title)).toEqual([A.title]);
    expect(out[0].metadata).toMatchObject({ passPhase: 2 });
  });

  it("keeps an authorization or logic candidate the validator rejected, labelled unconfirmed", async () => {
    analyze.mockResolvedValue(JSON.stringify({ findings: [confirm(A)] }));
    const out = await run();
    const b = out.find((f) => f.title === B.title)!;
    expect(b.metadata).toMatchObject({ validation: "unconfirmed" });
    expect(b.description).toMatch(/did not confirm this authorization or business-logic finding/);
    expect((out.find((f) => f.title === A.title)!.metadata as Record<string, unknown>).validation).toBeUndefined();
  });

  it("keeps candidates unconfirmed when the answer was cut off", async () => {
    const full = JSON.stringify({ findings: [confirm(A), confirm(B)] });
    analyze.mockResolvedValue(full.slice(0, full.lastIndexOf("populate_db")));
    const out = await run();
    const byTitle = Object.fromEntries(out.map((f) => [f.title, f.metadata as Record<string, unknown>]));
    expect(Object.keys(byTitle).sort()).toEqual([A.title, B.title].sort());
    expect(byTitle[A.title].validation).toBeUndefined(); // confirmed before the cut
    expect(byTitle[B.title].validation).toBe("unconfirmed");
  });

  it("tolerates a confirmed finding without a description", async () => {
    const { description: _omit, ...noDescription } = confirm(A);
    void _omit;
    analyze.mockResolvedValue(JSON.stringify({ findings: [noDescription] }));
    const a = (await run()).find((f) => f.title === A.title)!;
    // Confirmed (not kept as unconfirmed because the batch broke).
    expect((a.metadata as Record<string, unknown>).validation).toBeUndefined();
  });

  it("keeps every candidate when the answer is unreadable or the call fails", async () => {
    analyze.mockResolvedValueOnce("{");
    expect((await run()).map((f) => f.title)).toEqual([A.title, B.title]);
    analyze.mockRejectedValueOnce(new Error("402 Insufficient credits"));
    const out = await run();
    expect(out).toHaveLength(2);
    expect(out.every((f) => (f.metadata as Record<string, unknown>).validation === "unconfirmed")).toBe(true);
  });
});
