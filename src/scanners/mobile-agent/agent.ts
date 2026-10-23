/**
 * The agent deep-scan loop: glm-5.3 (via OpenRouter, function calling) drives an
 * E2B cloud sandbox to decompile/extract and inspect an uploaded mobile app.
 * A TypeScript port of the validated prototype (agent_apk_e2b.py), E2B-cloud
 * backend only (on-prem Docker comes later).
 *
 * The uploaded artifact is streamed into the VM (handles large files without
 * buffering it in memory); the model then installs whatever tools it needs and
 * drives the review with two tools — run_command / read_file — executed in the
 * sandbox. Reasoning and a short note per command stream back through
 * `onReasoning`; the model finishes by returning a findings-JSON block. The
 * sandbox is ALWAYS killed in a finally.
 */
import * as fs from "fs";
import OpenAI from "openai";
import { Sandbox } from "e2b";
import { logger } from "@/lib/logger";
import { agentScanSystemPrompt } from "./prompt";
import type { AgentScanConfig, WebSearchConfig } from "./config";

/** Chars of command output fed back to the model. */
const MAX_OUTPUT = 6000;
/** Default chars of a read file fed back to the model. */
const MAX_FILE = 12000;
/** Home of the E2B sandbox's default user; the artifact is uploaded here. */
const SANDBOX_HOME = "/home/user";

/** A finding the model streams mid-run via the report_finding tool. */
export interface ReportedFinding {
  title?: string;
  severity?: string;
  file?: string;
  line?: number | null;
  vulnerability?: string;
  attack?: string;
  fix?: string;
  confidence?: string;
  cwe?: string | null;
}

export interface AgentScanOptions {
  signal?: AbortSignal;
  /** Streamed reasoning + a short `$ <command>` note per tool call (buffered by the caller's sink). */
  onReasoning?: (delta: string) => void;
  /** Called once the sandbox exists, with its id, for visible scan status. */
  onSandbox?: (sandboxId: string | undefined) => void;
  /** Called each time the model reports a confirmed finding (report_finding tool), for live insertion. */
  onFinding?: (finding: ReportedFinding) => void | Promise<void>;
}

export interface AgentScanRun {
  /** The model's final answer — a findings-JSON string for the caller to parse. */
  content: string;
  /** The full reasoning + command trace, for storage / developer display. */
  reasoning: string;
  /** Model turns taken. */
  steps: number;
  /** True when the model finished on its own (returned a report) rather than hitting the step cap. */
  finished: boolean;
}

const BASE_TOOLS: OpenAI.Chat.Completions.ChatCompletionTool[] = [
  {
    type: "function",
    function: {
      name: "run_command",
      description:
        "Run a shell command in the sandbox (bash -lc). Returns stdout, stderr and exit code (truncated).",
      parameters: {
        type: "object",
        properties: { command: { type: "string" } },
        required: ["command"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "read_file",
      description:
        "Read a UTF-8 text file from the sandbox (e.g. a decompiled source). Returns up to max_bytes characters.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string" },
          max_bytes: { type: "integer" },
        },
        required: ["path"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "report_finding",
      description:
        "Report ONE confirmed security finding as soon as you have verified it — do not wait until the end. Each call is surfaced in the Findings tab immediately.",
      parameters: {
        type: "object",
        properties: {
          title: { type: "string" },
          severity: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
          file: { type: "string", description: "path inside the artifact, e.g. com/example/Login.java" },
          line: { type: ["integer", "null"] },
          vulnerability: { type: "string", description: "what the weakness is, grounded in the evidence" },
          attack: { type: "string", description: "how it is exploited / the risk (no payloads)" },
          fix: { type: "string", description: "the concrete remediation" },
          confidence: { type: "string", enum: ["high", "medium", "low"] },
          cwe: { type: ["string", "null"] },
        },
        required: ["title", "severity", "file", "vulnerability", "fix"],
      },
    },
  },
];

/** Offered only when a web search provider key is configured (self-gated). */
const WEB_SEARCH_TOOL: OpenAI.Chat.Completions.ChatCompletionTool = {
  type: "function",
  function: {
    name: "web_search",
    description:
      "Search the web for security advisories, CVEs and vendor docs to verify a finding. Returns the top results (title, url, snippet).",
    parameters: {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
    },
  },
};

/** Minimal slice of the E2B Sandbox this loop uses (keeps the loop testable). */
interface SandboxLike {
  sandboxId?: string;
  commands: {
    run: (
      cmd: string,
      opts?: { timeoutMs?: number; requestTimeoutMs?: number },
    ) => Promise<CommandResultLike>;
  };
  files: {
    write: (path: string, data: unknown) => Promise<unknown>;
    read: (path: string) => Promise<unknown>;
  };
  kill: () => Promise<unknown>;
}

interface CommandResultLike {
  exitCode: number;
  stdout: string;
  stderr: string;
  error?: string;
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + "\n… (truncated)" : s;
}

function formatCommandResult(exitCode: number, stdout: string, stderr: string): string {
  const combined = (stdout || "") + (stderr ? `\n[stderr]\n${stderr}` : "");
  return `exit=${exitCode}\n${truncate(combined, MAX_OUTPUT) || "(no output)"}`;
}

/** Runs a command, turning E2B's non-zero-exit throw back into a normal result for the model. */
async function runCommand(
  sandbox: SandboxLike,
  command: string,
  timeoutMs: number,
): Promise<string> {
  try {
    // Match the network request deadline to the command timeout, or E2B's
    // default ~60s request timeout would kill a long decompile (jadx) mid-run.
    const r = await sandbox.commands.run(command, { timeoutMs, requestTimeoutMs: timeoutMs });
    return formatCommandResult(r.exitCode, r.stdout, r.stderr);
  } catch (err) {
    // CommandExitError carries the result; surface it instead of failing the loop.
    const e = err as Partial<CommandResultLike> & { name?: string; message?: string };
    if (typeof e.exitCode === "number") {
      return formatCommandResult(e.exitCode, e.stdout || "", e.stderr || e.message || "");
    }
    return `ERROR: ${e.name || "Error"}: ${String(e.message || err).slice(0, 300)}`;
  }
}

async function readFile(sandbox: SandboxLike, path: string, cap: number): Promise<string> {
  try {
    const c = await sandbox.files.read(path);
    const text = typeof c === "string" ? c : String(c ?? "");
    return truncate(text, cap);
  } catch (err) {
    const e = err as { name?: string; message?: string };
    return `ERROR: ${e.name || "Error"}: ${String(e.message || err).slice(0, 300)}`;
  }
}

/** Max chars of web search results fed back to the model. */
const MAX_WEB_SEARCH = 4000;

interface WebResult {
  title?: string;
  url?: string;
  snippet?: string;
}

/** Runs a web search via the configured provider (Tavily or Brave). Worker-side fetch. */
async function webSearch(
  cfg: WebSearchConfig,
  query: string,
  signal?: AbortSignal,
): Promise<string> {
  try {
    let results: WebResult[] = [];
    if (cfg.provider === "brave") {
      const res = await fetch(
        `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=5`,
        { headers: { Accept: "application/json", "X-Subscription-Token": cfg.apiKey }, signal },
      );
      if (!res.ok) return `ERROR: web search failed (HTTP ${res.status})`;
      const data = (await res.json()) as { web?: { results?: Array<Record<string, unknown>> } };
      results = (data.web?.results ?? []).slice(0, 5).map((r) => ({
        title: r.title as string,
        url: r.url as string,
        snippet: (r.description as string) || "",
      }));
    } else {
      // Tavily (default)
      const res = await fetch("https://api.tavily.com/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: cfg.apiKey, query, max_results: 5 }),
        signal,
      });
      if (!res.ok) return `ERROR: web search failed (HTTP ${res.status})`;
      const data = (await res.json()) as { results?: Array<Record<string, unknown>> };
      results = (data.results ?? []).slice(0, 5).map((r) => ({
        title: r.title as string,
        url: r.url as string,
        snippet: (r.content as string) || "",
      }));
    }
    if (results.length === 0) return "(no results)";
    const text = results
      .map((r) => `- ${r.title || "(untitled)"}\n  ${r.url || ""}\n  ${(r.snippet || "").slice(0, 300)}`)
      .join("\n");
    return truncate(text, MAX_WEB_SEARCH);
  } catch (err) {
    const e = err as { name?: string; message?: string };
    return `ERROR: ${e.name || "Error"}: ${String(e.message || err).slice(0, 300)}`;
  }
}

async function dispatchTool(
  sandbox: SandboxLike,
  name: string,
  args: Record<string, unknown>,
  cfg: AgentScanConfig,
  signal?: AbortSignal,
): Promise<string> {
  if (name === "run_command") {
    const command = typeof args.command === "string" ? args.command : "";
    if (!command) return "ERROR: no command provided";
    return runCommand(sandbox, command, cfg.cmdTimeoutMs);
  }
  if (name === "read_file") {
    const path = typeof args.path === "string" ? args.path : "";
    if (!path) return "ERROR: no path provided";
    const cap = typeof args.max_bytes === "number" && args.max_bytes > 0 ? args.max_bytes : MAX_FILE;
    return readFile(sandbox, path, cap);
  }
  if (name === "web_search") {
    if (!cfg.webSearch) return "ERROR: web_search is not available";
    const query = typeof args.query === "string" ? args.query : "";
    if (!query) return "ERROR: no query provided";
    return webSearch(cfg.webSearch, query, signal);
  }
  return `unknown tool ${name}`;
}

/** Extracts OpenRouter's non-standard `reasoning` field from a message (string or detail array). */
function extractReasoning(msg: unknown): string {
  const m = msg as { reasoning?: unknown; reasoning_details?: unknown };
  if (typeof m.reasoning === "string") return m.reasoning;
  if (Array.isArray(m.reasoning_details)) {
    return m.reasoning_details
      .map((d) =>
        d && typeof d === "object"
          ? ((d as Record<string, unknown>).text as string) ||
            ((d as Record<string, unknown>).summary as string) ||
            ""
          : "",
      )
      .join("");
  }
  return "";
}

/**
 * Runs the agent review of `localArtifactPath` (an .apk/.aab/.ipa or source
 * archive) in a fresh E2B sandbox named after `artifactName`. The sandbox is
 * always torn down.
 */
export async function runAgentScan(
  localArtifactPath: string,
  artifactName: string,
  cfg: AgentScanConfig,
  opts: AgentScanOptions = {},
): Promise<AgentScanRun> {
  const client = new OpenAI({ apiKey: cfg.openRouterApiKey, baseURL: cfg.baseUrl });
  const sandbox = (await Sandbox.create({
    apiKey: cfg.e2bApiKey,
    timeoutMs: cfg.sandboxTimeoutMs,
  })) as unknown as SandboxLike;
  opts.onSandbox?.(sandbox.sandboxId);

  const remotePath = `${SANDBOX_HOME}/${artifactName}`;
  const emit = (s: string) => {
    if (s) opts.onReasoning?.(s);
  };

  try {
    // Stream the artifact into the VM — a Blob reads from disk lazily, so a
    // large upload is not buffered in the worker's memory.
    const blob = await fs.openAsBlob(localArtifactPath);
    await sandbox.files.write(remotePath, blob);

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: agentScanSystemPrompt(remotePath) },
      { role: "user", content: `Review ${remotePath} and report the security findings as JSON.` },
    ];

    let reasoningAll = "";
    let steps = 0;

    // Offer web_search only when a provider key is configured (self-gated).
    const tools = cfg.webSearch ? [...BASE_TOOLS, WEB_SEARCH_TOOL] : BASE_TOOLS;

    // reasoning passthrough is an OpenRouter extension, not in the OpenAI types.
    const baseParams = {
      model: cfg.model,
      tools,
      tool_choice: "auto" as const,
      reasoning: { enabled: true, effort: "high" },
    };

    for (; steps < cfg.maxSteps; steps++) {
      if (opts.signal?.aborted) break;

      const resp = await client.chat.completions.create(
        { ...baseParams, messages } as OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming,
        { signal: opts.signal },
      );
      const msg = resp.choices[0]?.message;
      if (!msg) break;

      const reasoning = extractReasoning(msg);
      if (reasoning) {
        reasoningAll += reasoning;
        emit(reasoning);
      }

      const toolCalls = msg.tool_calls ?? [];
      if (toolCalls.length === 0) {
        // The model is done: its content is the findings JSON.
        return { content: msg.content ?? "", reasoning: reasoningAll, steps: steps + 1, finished: true };
      }

      messages.push({
        role: "assistant",
        content: msg.content ?? "",
        tool_calls: toolCalls,
      });

      for (const tc of toolCalls) {
        if (tc.type !== "function") {
          messages.push({ role: "tool", tool_call_id: tc.id, content: "unsupported tool call" });
          continue;
        }
        let args: Record<string, unknown> = {};
        try {
          args = JSON.parse(tc.function.arguments || "{}");
        } catch {
          args = {};
        }
        // report_finding streams one confirmed finding for immediate insertion.
        if (tc.function.name === "report_finding") {
          const note = `\n(reported: ${String(args.title ?? "").slice(0, 120)})\n`;
          reasoningAll += note;
          emit(note);
          try {
            await opts.onFinding?.(args as ReportedFinding);
          } catch {
            /* live insertion is best-effort; the final JSON is the safety net */
          }
          messages.push({ role: "tool", tool_call_id: tc.id, content: "finding recorded" });
          continue;
        }

        let note: string;
        if (tc.function.name === "run_command") {
          note = `\n$ ${String(args.command ?? "").slice(0, 300)}\n`;
        } else if (tc.function.name === "web_search") {
          note = `\n(web_search "${String(args.query ?? "").slice(0, 200)}")\n`;
        } else {
          note = `\n(read ${String(args.path ?? "")})\n`;
        }
        reasoningAll += note;
        emit(note);
        const result = await dispatchTool(sandbox, tc.function.name, args, cfg, opts.signal);
        messages.push({ role: "tool", tool_call_id: tc.id, content: result });
      }
    }

    // Hit the step cap (or aborted) without a final report: ask once, plainly,
    // for the findings JSON so the scan still produces a result.
    if (opts.signal?.aborted) {
      return { content: "", reasoning: reasoningAll, steps, finished: false };
    }
    const final = await client.chat.completions.create(
      {
        model: cfg.model,
        messages: [
          ...messages,
          {
            role: "user",
            content:
              "Stop investigating now and return your final findings as JSON only, in the shape specified.",
          },
        ],
        tool_choice: "none",
        reasoning: { enabled: true, effort: "high" },
      } as OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming,
      { signal: opts.signal },
    );
    const finalMsg = final.choices[0]?.message;
    const finalReasoning = extractReasoning(finalMsg);
    if (finalReasoning) reasoningAll += finalReasoning;
    return { content: finalMsg?.content ?? "", reasoning: reasoningAll, steps, finished: false };
  } finally {
    try {
      await sandbox.kill();
    } catch (err) {
      logger.warn(
        { err: err instanceof Error ? err.message : String(err) },
        "[agent-scan] failed to kill E2B sandbox",
      );
    }
  }
}

/** @deprecated renamed to {@link runAgentScan}. */
export const runMobileAgent = runAgentScan;
/** @deprecated renamed to {@link AgentScanOptions}. */
export type MobileAgentOptions = AgentScanOptions;
/** @deprecated renamed to {@link AgentScanRun}. */
export type MobileAgentRun = AgentScanRun;
