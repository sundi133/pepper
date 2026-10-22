import { describe, it, expect, vi } from "vitest";
import { analyzeWithLlm } from "./llm-gateway";
import type { LlmClient } from "./llm-gateway";

async function* streamOf(chunks: unknown[]) {
  for (const c of chunks) yield c;
}

// ─── Ollama ───────────────────────────────────────────────────────────

type OllamaChat = (req: { stream?: boolean }) => Promise<unknown>;

function ollamaClient(chat: OllamaChat): LlmClient {
  return {
    type: "ollama",
    client: { chat },
    model: "qwen3",
  } as unknown as LlmClient;
}

describe("analyzeWithLlm reasoning capture — Ollama", () => {
  it("enables think + stream and captures message.thinking deltas", async () => {
    const chat = vi.fn<OllamaChat>(async (req) =>
      req.stream
        ? streamOf([
            { message: { thinking: "weighing the sink", content: "" } },
            { message: { thinking: " and the source", content: "" } },
            { message: { thinking: "", content: '{"findings":[]}' } },
          ])
        : { message: { content: "{}" } },
    );
    const seen: string[] = [];
    const out = await analyzeWithLlm(ollamaClient(chat), "", "sys", "user", {
      onReasoning: (d) => seen.push(d),
    });
    expect(seen.join("")).toBe("weighing the sink and the source");
    expect(out).toBe('{"findings":[]}');
    expect(chat).toHaveBeenCalledOnce();
    const req = chat.mock.calls[0][0] as { stream?: boolean; think?: boolean };
    expect(req.stream).toBe(true);
    expect(req.think).toBe(true);
  });

  it("falls back to the non-streaming call if the think stream fails", async () => {
    const chat = vi.fn<OllamaChat>(async (req) => {
      if (req.stream) throw new Error("model does not support thinking");
      return { message: { content: '{"fallback":true}' } };
    });
    const out = await analyzeWithLlm(ollamaClient(chat), "", "sys", "user", {
      onReasoning: () => {
        throw new Error("should not be called on fallback");
      },
    });
    expect(out).toBe('{"fallback":true}');
    expect(chat).toHaveBeenCalledTimes(2); // stream attempt + fallback
  });

  it("makes a plain non-streaming call when no onReasoning is given", async () => {
    const chat = vi.fn<OllamaChat>(async () => ({ message: { content: "{}" } }));
    await analyzeWithLlm(ollamaClient(chat), "", "sys", "user");
    expect(chat).toHaveBeenCalledOnce();
    const req = chat.mock.calls[0][0] as { stream?: boolean; think?: boolean };
    expect(req.stream).toBeUndefined();
    expect(req.think).toBeUndefined();
  });
});

// ─── Anthropic ──────────────────────────────────────────────────────────

function anthropicClient(
  streamFn: (p: unknown) => AsyncIterable<unknown>,
  createFn: (p: unknown) => Promise<unknown>,
): LlmClient {
  return {
    type: "anthropic",
    client: { messages: { stream: streamFn, create: createFn } },
    model: "claude-opus-4-8",
  } as unknown as LlmClient;
}

describe("analyzeWithLlm reasoning capture — Anthropic", () => {
  it("streams thinking_delta and accumulates text_delta as content", async () => {
    const stream = vi.fn(() =>
      streamOf([
        { type: "content_block_delta", delta: { type: "thinking_delta", thinking: "let me trace" } },
        { type: "content_block_delta", delta: { type: "thinking_delta", thinking: " the taint" } },
        { type: "content_block_delta", delta: { type: "text_delta", text: '{"findings":[]}' } },
      ]),
    );
    const create = vi.fn(async () => ({ content: [{ type: "text", text: "{}" }] }));
    const seen: string[] = [];
    const out = await analyzeWithLlm(anthropicClient(stream, create), "", "sys", "user", {
      onReasoning: (d) => seen.push(d),
    });
    expect(seen.join("")).toBe("let me trace the taint");
    expect(out).toBe('{"findings":[]}');
    expect(stream).toHaveBeenCalledOnce();
    expect(create).not.toHaveBeenCalled();
    const params = (stream.mock.calls[0] as unknown[])[0] as {
      thinking?: { type: string };
      temperature?: number;
    };
    expect(params.thinking?.type).toBe("enabled");
    // Thinking requires the default temperature; the param is omitted.
    expect(params.temperature).toBeUndefined();
  });

  it("falls back to the non-streaming create when thinking stream fails", async () => {
    const stream = vi.fn((): AsyncIterable<unknown> => {
      throw new Error("thinking unsupported for this model");
    });
    const create = vi.fn(async () => ({
      content: [{ type: "text", text: '{"fallback":true}' }],
    }));
    const out = await analyzeWithLlm(anthropicClient(stream, create), "", "sys", "user", {
      onReasoning: () => {
        throw new Error("should not be called on fallback");
      },
    });
    expect(out).toBe('{"fallback":true}');
    expect(stream).toHaveBeenCalledOnce();
    expect(create).toHaveBeenCalledOnce();
  });

  it("makes a plain non-streaming call when no onReasoning is given", async () => {
    const stream = vi.fn(() => streamOf([]));
    const create = vi.fn(async () => ({ content: [{ type: "text", text: "{}" }] }));
    await analyzeWithLlm(anthropicClient(stream, create), "", "sys", "user");
    expect(stream).not.toHaveBeenCalled();
    expect(create).toHaveBeenCalledOnce();
  });
});

// ─── Azure AI Foundry ────────────────────────────────────────────────────

type CreateFn = (params: { stream?: boolean }) => Promise<unknown>;

function azureClient(create: CreateFn): LlmClient {
  return {
    type: "azure",
    client: { chat: { completions: { create } } },
    model: "glm-4.6",
  } as unknown as LlmClient;
}

describe("analyzeWithLlm reasoning capture — Azure Foundry", () => {
  it("captures reasoning deltas from a streamed call", async () => {
    const create = vi.fn<CreateFn>(async (params) =>
      params.stream
        ? streamOf([
            { choices: [{ delta: { reasoning: "inspecting" } }] },
            { choices: [{ delta: { reasoning: " the handler" } }] },
            { choices: [{ delta: { content: '{"findings":[]}' } }] },
          ])
        : { choices: [{ message: { content: "{}" } }] },
    );
    const seen: string[] = [];
    const out = await analyzeWithLlm(azureClient(create), "", "sys", "user", {
      onReasoning: (d) => seen.push(d),
    });
    expect(seen.join("")).toBe("inspecting the handler");
    expect(out).toBe('{"findings":[]}');
    expect(create).toHaveBeenCalledOnce();
    expect(create.mock.calls[0][0].stream).toBe(true);
  });

  it("falls back to foundryChat (non-streaming) when the stream fails", async () => {
    const create = vi.fn<CreateFn>(async (params) => {
      if (params.stream) throw new Error("streaming unsupported");
      return { choices: [{ message: { content: '{"fallback":true}' } }] };
    });
    const out = await analyzeWithLlm(azureClient(create), "", "sys", "user", {
      onReasoning: () => {
        throw new Error("should not be called on fallback");
      },
    });
    expect(out).toBe('{"fallback":true}');
    expect(create).toHaveBeenCalledTimes(2); // stream attempt + foundryChat
    expect(create.mock.calls[1][0].stream).toBeUndefined();
  });

  it("uses foundryChat directly when no onReasoning is given", async () => {
    const create = vi.fn<CreateFn>(async () => ({
      choices: [{ message: { content: "{}" } }],
    }));
    await analyzeWithLlm(azureClient(create), "", "sys", "user");
    expect(create).toHaveBeenCalledOnce();
    expect(create.mock.calls[0][0].stream).toBeUndefined();
  });
});
