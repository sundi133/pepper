import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getActiveOrgId: vi.fn(async () => "o1"),
  requireRole: vi.fn(async () => ({ ok: true })),
}));

const findingFindFirst = vi.fn();
const findingFindUnique = vi.fn();
const findingUpdate = vi.fn();
vi.mock("@/lib/prisma", () => ({
  prisma: {
    finding: {
      findFirst: (...a: unknown[]) => findingFindFirst(...a),
      findUnique: (...a: unknown[]) => findingFindUnique(...a),
      update: (...a: unknown[]) => findingUpdate(...a),
    },
  },
}));

const llmConfig = { provider: "openai", baseUrl: "", apiKey: "k", model: "m" };
vi.mock("@/lib/llm-gateway", () => ({ getLlmConfig: vi.fn(() => llmConfig) }));

const generate = vi.fn();
vi.mock("@/lib/generate-finding-details", () => ({
  generateFindingDetails: (...a: unknown[]) => generate(...a),
}));

import { POST } from "./route";

const details = { summary: "s", impact: "i", generatedAt: "t" };

function finding(metadata: Record<string, unknown> = {}) {
  return {
    id: "f1",
    title: "XSS",
    cweId: "CWE-79",
    severity: "HIGH",
    filePath: "a.asp",
    startLine: 1,
    endLine: 2,
    description: "d",
    metadata,
    scan: { project: { organizationId: "o1", organization: { settings: {} } } },
  };
}

const call = (query = "") =>
  POST(new NextRequest(`http://localhost/api/findings/f1/generate-details${query}`, { method: "POST" }), {
    params: Promise.resolve({ findingId: "f1" }),
  });

beforeEach(() => {
  vi.clearAllMocks();
  llmConfig.apiKey = "k";
  findingFindFirst.mockResolvedValue(finding());
  findingFindUnique.mockResolvedValue({ metadata: { status: "kept" } });
  findingUpdate.mockResolvedValue({});
});

afterEach(() => {
  vi.useRealTimers();
});

describe("POST /api/findings/:id/generate-details", () => {
  it("returns stored details without calling the model", async () => {
    findingFindFirst.mockResolvedValue(finding({ generatedDetails: details }));
    const res = await call();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(details);
    expect(generate).not.toHaveBeenCalled();
  });

  it("regenerates stored details when asked", async () => {
    findingFindFirst.mockResolvedValue(finding({ generatedDetails: { summary: "old" } }));
    generate.mockResolvedValue(details);
    const res = await call("?regenerate=1");
    expect(res.status).toBe(200);
    expect(generate).toHaveBeenCalledTimes(1);
  });

  it("generates, then saves onto the latest metadata", async () => {
    generate.mockResolvedValue(details);
    const res = await call();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual(details);
    expect(findingUpdate).toHaveBeenCalledWith({
      where: { id: "f1" },
      data: { metadata: { status: "kept", generatedDetails: details } },
    });
  });

  it("says no model is configured instead of failing generically", async () => {
    llmConfig.apiKey = "";
    const res = await call();
    expect(res.status).toBe(409);
    expect((await res.json()).error).toMatch(/AI Models/);
    expect(generate).not.toHaveBeenCalled();
  });

  it("reports an unreadable answer and a provider failure separately", async () => {
    generate.mockResolvedValueOnce(null);
    const unreadable = await call();
    expect(unreadable.status).toBe(502);
    expect((await unreadable.json()).error).toMatch(/couldn't be read/);

    generate.mockRejectedValueOnce(new Error("rate limited"));
    const failed = await call();
    expect(failed.status).toBe(502);
    expect((await failed.json()).error).toMatch(/rate limited/);
  });

  it("joins a running generation instead of starting a second one", async () => {
    let finish!: (v: unknown) => void;
    generate.mockReturnValue(new Promise((r) => (finish = r)));
    const first = call();
    const second = call();
    await vi.waitFor(() => expect(generate).toHaveBeenCalledTimes(1));
    finish(details);
    const [a, b] = await Promise.all([first, second]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(generate).toHaveBeenCalledTimes(1);
  });

  it("answers 202 after the wait limit and still saves the result", async () => {
    vi.useFakeTimers();
    let finish!: (v: unknown) => void;
    generate.mockReturnValue(new Promise((r) => (finish = r)));
    const pending = call();
    await vi.waitFor(() => expect(generate).toHaveBeenCalled());
    await vi.advanceTimersByTimeAsync(45_000);
    const res = await pending;
    expect(res.status).toBe(202);
    expect(res.headers.get("Retry-After")).toBe("15");

    finish(details);
    await vi.waitFor(() => expect(findingUpdate).toHaveBeenCalled());
  });
});
