import { describe, it, expect } from "vitest";
import { parseLlmJsonObject, repairJsonObject } from "./llm-gateway";

describe("parseLlmJsonObject (issue #213)", () => {
  it("parses clean JSON, fenced JSON and JSON surrounded by prose", () => {
    expect(parseLlmJsonObject('{"summary":"a"}')).toEqual({ value: { summary: "a" }, status: "ok" });
    expect(parseLlmJsonObject('```json\n{"summary":"a"}\n```')?.value).toEqual({ summary: "a" });
    expect(parseLlmJsonObject('Here you go:\n{"summary":"a"}\nThanks')?.value).toEqual({ summary: "a" });
  });

  it("repairs raw line breaks and tabs inside string values", () => {
    const raw = '{"stepsToReproduce": "1. Send it\n   ```bash\n   curl -X POST\t/x\n   ```", "impact": "x"}';
    const parsed = parseLlmJsonObject<{ stepsToReproduce: string; impact: string }>(raw);
    expect(parsed?.status).toBe("recovered");
    expect(parsed?.value.stepsToReproduce).toBe("1. Send it\n   ```bash\n   curl -X POST\t/x\n   ```");
    expect(parsed?.value.impact).toBe("x");
  });

  it("recovers an answer cut off mid-string, keeping the complete fields", () => {
    const raw = '{"summary": "Reflected XSS.", "impact": "* Session theft.", "remediation": "* Encode outp';
    expect(parseLlmJsonObject(raw)).toEqual({
      value: { summary: "Reflected XSS.", impact: "* Session theft." },
      status: "recovered",
    });
  });

  it("recovers a cut-off answer after a dangling key or comma, and inside arrays", () => {
    expect(parseLlmJsonObject('{"a": "1", "b')?.value).toEqual({ a: "1" });
    expect(parseLlmJsonObject('{"a": "1",')?.value).toEqual({ a: "1" });
    expect(parseLlmJsonObject('{"a": ["x", "y", "z')?.value).toEqual({ a: ["x", "y"] });
    expect(parseLlmJsonObject('{"n": 5, "ok": true, "s": "t')?.value).toEqual({ n: 5, ok: true });
  });

  it("keeps escaped quotes and braces inside strings intact", () => {
    const raw = '{"summary": "Use \\"quotes\\" and {braces}", "x": "y';
    expect(parseLlmJsonObject(raw)?.value).toEqual({ summary: 'Use "quotes" and {braces}' });
  });

  it("returns null when there is no object to recover", () => {
    expect(parseLlmJsonObject("I can't help with that.")).toBeNull();
    expect(parseLlmJsonObject('{"summ')).toBeNull();
    expect(parseLlmJsonObject("[1, 2]")).toBeNull();
  });
});

describe("repairJsonObject", () => {
  it("stops at the end of the first complete object", () => {
    expect(repairJsonObject('{"a":1} trailing {"b":2}')).toBe('{"a":1}');
  });
});
