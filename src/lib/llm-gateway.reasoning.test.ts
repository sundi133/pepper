import { describe, it, expect, vi } from "vitest";
import { analyzeWithLlm } from "./llm-gateway";
import type { LlmClient } from "./llm-gateway";

type CreateFn = (params: { stream?: boolean }) => Promise<unknown>;

function fakeClient(create: CreateFn): LlmClient {
  return {
    type: "openrouter",
    client: { chat: { completions: { create } } },
    model: "z-ai/glm-5.3",
  } as unknown as LlmClient;
}

async function* streamOf(chunks: unknown[]) {
  for (const c of chunks) yield c;
}

describe("analyzeWithLlm reasoning capture", () => {
  it("captures reasoning deltas and returns content when the model streams them", async () => {
    const create = vi.fn<CreateFn>(async (params) =>
      params.stream
        ? streamOf([
            { choices: [{ delta: { reasoning: "I check the sink" } }] },
            { choices: [{ delta: { reasoning: " then the source." } }] },
            { choices: [{ delta: { content: '{"findings":[]}' } }] },
          ])
        : { choices: [{ message: { content: "{}" } }] },
    );
    const seen: string[] = [];
    const out = await analyzeWithLlm(fakeClient(create), "", "sys", "user", {
      onReasoning: (d) => seen.push(d),
    });
    expect(seen.join("")).toBe("I check the sink then the source.");
    expect(out).toBe('{"findings":[]}');
    expect(create).toHaveBeenCalledOnce();
    expect(create.mock.calls[0][0].stream).toBe(true);
  });

  it("falls back to the normal call if streaming fails (non-reasoning safety)", async () => {
    const create = vi.fn<CreateFn>(async (params) => {
      if (params.stream) throw new Error("streaming unsupported");
      return { choices: [{ message: { content: '{"fallback":true}' } }] };
    });
    const out = await analyzeWithLlm(fakeClient(create), "", "sys", "user", {
      onReasoning: () => {
        throw new Error("should not be called on fallback");
      },
    });
    expect(out).toBe('{"fallback":true}');
    expect(create).toHaveBeenCalledTimes(2); // stream attempt + fallback
  });

  it("makes a plain non-streaming call when no onReasoning is given (unchanged behavior)", async () => {
    const create = vi.fn<CreateFn>(async () => ({
      choices: [{ message: { content: "{}" } }],
    }));
    await analyzeWithLlm(fakeClient(create), "", "sys", "user");
    expect(create).toHaveBeenCalledOnce();
    expect(create.mock.calls[0][0].stream).toBeUndefined();
  });
});
