import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// Mock the OpenAI client and the E2B Sandbox so the loop runs with no network.
const { create, sandboxCreate, run, write, read, kill, warn } = vi.hoisted(() => ({
  create: vi.fn(),
  sandboxCreate: vi.fn(),
  run: vi.fn(),
  write: vi.fn(),
  read: vi.fn(),
  kill: vi.fn(),
  warn: vi.fn(),
}));

vi.mock("openai", () => ({
  default: class {
    chat = { completions: { create } };
  },
}));
vi.mock("e2b", () => ({ Sandbox: { create: sandboxCreate } }));
vi.mock("@/lib/logger", () => ({ logger: { warn, error: vi.fn(), info: vi.fn() } }));

import { runAgentScan } from "./agent";
import type { AgentScanConfig } from "./config";

const CFG: AgentScanConfig = {
  openRouterApiKey: "sk-or-test",
  e2bApiKey: "e2b-test",
  model: "z-ai/glm-5.3",
  baseUrl: "https://openrouter.ai/api/v1",
  keySource: "env",
  maxSteps: 50,
  sandboxTimeoutMs: 1_800_000,
  cmdTimeoutMs: 240_000,
};

/** A response with one run_command tool call. */
function toolCallResponse(command: string, reasoning = "") {
  return {
    choices: [
      {
        message: {
          content: "",
          reasoning,
          tool_calls: [
            {
              id: "call_1",
              type: "function",
              function: { name: "run_command", arguments: JSON.stringify({ command }) },
            },
          ],
        },
      },
    ],
  };
}

/** A response with one web_search tool call. */
function webSearchResponse(query: string) {
  return {
    choices: [
      {
        message: {
          content: "",
          reasoning: "",
          tool_calls: [
            {
              id: "call_ws",
              type: "function",
              function: { name: "web_search", arguments: JSON.stringify({ query }) },
            },
          ],
        },
      },
    ],
  };
}

const WS_CFG = { apiKey: "ws-key", provider: "tavily" as const };

/** A final response (no tool calls) carrying the findings JSON. */
function finalResponse(findings: unknown[], reasoning = "") {
  return {
    choices: [
      { message: { content: JSON.stringify({ findings }), reasoning, tool_calls: [] } },
    ],
  };
}

let artifactPath: string;
let workDir: string;

beforeEach(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), "mobile-agent-loop-"));
  artifactPath = path.join(workDir, "app.apk");
  fs.writeFileSync(artifactPath, "PK\u0003\u0004 pretend apk bytes");

  create.mockReset();
  sandboxCreate.mockReset();
  run.mockReset();
  write.mockReset();
  read.mockReset();
  kill.mockReset();
  warn.mockReset();

  sandboxCreate.mockResolvedValue({
    sandboxId: "sbx_test",
    commands: { run },
    files: { write, read },
    kill,
  });
  write.mockResolvedValue(undefined);
  kill.mockResolvedValue(true);
});

afterEach(() => {
  fs.rmSync(workDir, { recursive: true, force: true });
});

describe("runMobileAgent", () => {
  it("uploads the artifact, runs the tool loop, and returns the final JSON", async () => {
    run.mockResolvedValue({ exitCode: 0, stdout: "jadx 1.4", stderr: "" });
    create
      .mockResolvedValueOnce(toolCallResponse("jadx --version", "thinking about tools"))
      .mockResolvedValueOnce(
        finalResponse([{ title: "Debuggable", severity: "MEDIUM" }], "wrapping up"),
      );

    const notes: string[] = [];
    const sandboxes: (string | undefined)[] = [];
    const result = await runAgentScan(artifactPath, "app.apk", CFG, {
      onReasoning: (d) => notes.push(d),
      onSandbox: (id) => sandboxes.push(id),
    });
    // the sandbox id is surfaced for visible status
    expect(sandboxes).toEqual(["sbx_test"]);

    // The sandbox was created with the E2B key and torn down.
    expect(sandboxCreate).toHaveBeenCalledWith(
      expect.objectContaining({ apiKey: "e2b-test", timeoutMs: CFG.sandboxTimeoutMs }),
    );
    expect(kill).toHaveBeenCalledOnce();

    // The artifact was uploaded to the sandbox home.
    expect(write).toHaveBeenCalledOnce();
    expect(write.mock.calls[0][0]).toBe("/home/user/app.apk");

    // The command the model asked for ran in the sandbox.
    expect(run).toHaveBeenCalledWith("jadx --version", { timeoutMs: CFG.cmdTimeoutMs });

    // Result + reasoning (model thinking and the `$ command` note) came back.
    expect(result.finished).toBe(true);
    expect(JSON.parse(result.content).findings[0].title).toBe("Debuggable");
    const trace = notes.join("");
    expect(trace).toContain("thinking about tools");
    expect(trace).toContain("$ jadx --version");
  });

  it("feeds a non-zero command result back to the model instead of throwing", async () => {
    // E2B throws CommandExitError on non-zero exit; it carries the result.
    run.mockRejectedValueOnce(
      Object.assign(new Error("exit 1"), { exitCode: 1, stdout: "", stderr: "not found" }),
    );
    create
      .mockResolvedValueOnce(toolCallResponse("apktool d app.apk"))
      .mockResolvedValueOnce(finalResponse([]));

    const result = await runAgentScan(artifactPath, "app.apk", CFG, {});

    expect(result.finished).toBe(true);
    // The tool result given to the model carried exit=1 and stderr.
    const toolMsg = create.mock.calls[1][0].messages.find(
      (m: { role: string }) => m.role === "tool",
    );
    expect(toolMsg.content).toContain("exit=1");
    expect(toolMsg.content).toContain("not found");
    expect(kill).toHaveBeenCalledOnce();
  });

  it("stops at the step cap and makes one forced final request for the JSON", async () => {
    run.mockResolvedValue({ exitCode: 0, stdout: "ok", stderr: "" });
    // Always asks for another tool call; with maxSteps=1 the loop body runs once.
    create.mockResolvedValue(toolCallResponse("ls -la"));
    // The forced final call (tool_choice: none) returns the JSON.
    create.mockResolvedValueOnce(toolCallResponse("ls -la"));
    create.mockResolvedValueOnce(finalResponse([{ title: "Late finding", severity: "LOW" }]));

    const result = await runAgentScan(artifactPath, "app.apk", { ...CFG, maxSteps: 1 }, {});

    expect(result.finished).toBe(false);
    expect(JSON.parse(result.content).findings[0].title).toBe("Late finding");
    // The forced request disabled tools.
    const lastCall = create.mock.calls[create.mock.calls.length - 1][0];
    expect(lastCall.tool_choice).toBe("none");
    expect(kill).toHaveBeenCalledOnce();
  });

  it("always kills the sandbox even when the model call throws", async () => {
    create.mockRejectedValueOnce(new Error("openrouter 500"));
    await expect(runAgentScan(artifactPath, "app.apk", CFG, {})).rejects.toThrow(
      "openrouter 500",
    );
    expect(kill).toHaveBeenCalledOnce();
  });

  it("does not make the forced final request when aborted", async () => {
    const controller = new AbortController();
    run.mockImplementation(async () => {
      controller.abort();
      return { exitCode: 0, stdout: "", stderr: "" };
    });
    create.mockResolvedValue(toolCallResponse("sleep 1"));

    const result = await runAgentScan(artifactPath, "app.apk", { ...CFG, maxSteps: 5 }, {
      signal: controller.signal,
    });

    expect(result.finished).toBe(false);
    expect(result.content).toBe("");
    expect(kill).toHaveBeenCalledOnce();
  });

  const toolNames = (call: unknown): string[] =>
    ((call as { tools?: Array<{ function: { name: string } }> }).tools ?? []).map(
      (t) => t.function.name,
    );

  it("offers only run_command + read_file when no web search provider is configured", async () => {
    run.mockResolvedValue({ exitCode: 0, stdout: "", stderr: "" });
    create.mockResolvedValueOnce(finalResponse([]));
    await runAgentScan(artifactPath, "app.apk", CFG, {});
    expect(toolNames(create.mock.calls[0][0])).toEqual(["run_command", "read_file"]);
  });

  it("offers a web_search tool when a provider key is configured", async () => {
    create.mockResolvedValueOnce(finalResponse([]));
    await runAgentScan(artifactPath, "app.apk", { ...CFG, webSearch: WS_CFG }, {});
    expect(toolNames(create.mock.calls[0][0])).toContain("web_search");
  });

  it("runs a web_search tool call via the provider fetch and feeds results back", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        results: [{ title: "CVE-2021-44228 (Log4Shell)", url: "https://x", content: "RCE in log4j" }],
      }),
    });
    vi.stubGlobal("fetch", fetchMock);
    try {
      create
        .mockResolvedValueOnce(webSearchResponse("log4j 2.14 CVE"))
        .mockResolvedValueOnce(finalResponse([]));
      await runAgentScan(artifactPath, "app.apk", { ...CFG, webSearch: WS_CFG }, {});
      expect(fetchMock).toHaveBeenCalledWith(
        "https://api.tavily.com/search",
        expect.objectContaining({ method: "POST" }),
      );
      const toolMsg = create.mock.calls[1][0].messages.find(
        (m: { role: string }) => m.role === "tool",
      );
      expect(toolMsg.content).toContain("CVE-2021-44228");
      expect(kill).toHaveBeenCalledOnce();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
