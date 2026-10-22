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

describe("analyzeWithLlm reasoning-model param adaptation", () => {
  function openaiClient(
    create: (p: Record<string, unknown>) => Promise<unknown>,
  ): LlmClient {
    return {
      type: "openai",
      client: { chat: { completions: { create } } },
      model: "gpt-6-astra",
    } as unknown as LlmClient;
  }

  it("retries max_tokens -> max_completion_tokens when the model rejects it", async () => {
    const create = vi.fn(async (p: Record<string, unknown>) => {
      if ("max_tokens" in p) {
        throw new Error(
          "Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead.",
        );
      }
      return { choices: [{ message: { content: '{"ok":1}' } }] };
    });
    const out = await analyzeWithLlm(openaiClient(create), "", "sys", "user");
    expect(out).toBe('{"ok":1}');
    expect("max_tokens" in create.mock.calls[0][0]).toBe(true);
    expect("max_completion_tokens" in create.mock.calls[1][0]).toBe(true);
  });

  it("drops an unsupported temperature after the token swap", async () => {
    const create = vi.fn(async (p: Record<string, unknown>) => {
      if ("max_tokens" in p) throw new Error("use 'max_completion_tokens' instead");
      if ("temperature" in p)
        throw new Error("Unsupported value: 'temperature' does not support 0.1");
      return { choices: [{ message: { content: '{"ok":2}' } }] };
    });
    const out = await analyzeWithLlm(openaiClient(create), "", "sys", "user");
    expect(out).toBe('{"ok":2}');
    const last = create.mock.calls[create.mock.calls.length - 1][0];
    expect("temperature" in last).toBe(false);
    expect("max_completion_tokens" in last).toBe(true);
  });
});
