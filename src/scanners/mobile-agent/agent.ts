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

// ─── Deterministic iOS pre-extraction ─────────────────────────────────────
// iOS on Linux has no decompiler and the Mach-O tools the model reaches for
// (otool/class-dump/radare2) are not in the VM — pure autonomy flails and hits
// the step cap. So for an .ipa we run a FIXED extraction (ported from the proven
// e2b_ipa_demo.py prototype) and hand the model real artifacts to review.

/** Runs inside the sandbox: parse Info.plist (plistlib handles binary plists) + Mach-O posture via macholib. */
const IOS_ANALYZE_PY = String.raw`
import plistlib, glob, os, json
try:
    from macholib.MachO import MachO
    from macholib import mach_o as mo
except Exception:
    MachO = None
apps = glob.glob('/tmp/out/Payload/*.app')
app = apps[0] if apps else None
os.makedirs('/tmp/ios', exist_ok=True)
pl = {}
if app:
    try:
        with open(os.path.join(app, 'Info.plist'), 'rb') as f:
            pl = plistlib.load(f)
    except Exception:
        pl = {}
with open('/tmp/ios/Info.plist.xml', 'wb') as f:
    f.write(plistlib.dumps(pl))
exe = pl.get('CFBundleExecutable') or (os.path.basename(app)[:-4] if app else '')
exe_path = os.path.join(app, exe) if app else ''
encrypted, pie, dylibs = False, None, []
if MachO and exe_path and os.path.exists(exe_path):
    try:
        m = MachO(exe_path)
        for hdr in m.headers:
            pie = bool(hdr.header.flags & mo.MH_PIE)
            for lc, cmd, data in hdr.commands:
                if lc.cmd in (mo.LC_LOAD_DYLIB, getattr(mo, 'LC_LOAD_WEAK_DYLIB', -1)):
                    try:
                        dylibs.append(bytes(data).split(b'\x00', 1)[0].decode('utf-8', 'ignore'))
                    except Exception:
                        pass
                if lc.cmd in (getattr(mo, 'LC_ENCRYPTION_INFO', -1), getattr(mo, 'LC_ENCRYPTION_INFO_64', -1)):
                    if getattr(cmd, 'cryptid', 0):
                        encrypted = True
    except Exception as e:
        print('MACHO_ERR', e)
with open('/tmp/ios/posture.json', 'w') as f:
    json.dump({'exe': exe_path, 'pie': pie, 'encrypted': encrypted, 'dylibs': sorted(set(dylibs))}, f, indent=2, default=str)
meta = {
    'app': app, 'exe': exe_path,
    'bundle_id': pl.get('CFBundleIdentifier'), 'min_os': pl.get('MinimumOSVersion'),
    'url_schemes': [t.get('CFBundleURLSchemes') for t in pl.get('CFBundleURLTypes', []) if isinstance(t, dict)],
    'ats': pl.get('NSAppTransportSecurity'),
    'permissions': {k: v for k, v in pl.items() if str(k).startswith('NS') and str(k).endswith('UsageDescription')},
}
with open('/tmp/ios/meta.json', 'w') as f:
    json.dump(meta, f, indent=2, default=str)
print(exe_path)
print('ENCRYPTED' if encrypted else 'NOT_ENCRYPTED')
`;

const IOS_STRING_BUCKETS: Record<string, RegExp> = {
  "secrets/urls":
    /(https?:\/\/[^ ]+|api[_-]?key|apikey|secret|token|password|passwd|AKIA[0-9A-Z]{16}|sk_live_|sk_test_|AIza[0-9A-Za-z_-]{20,})/i,
  crypto: /(kCCAlgorithmDES|ECB|CC_MD5|CC_SHA1|CCCrypt|CommonCrypto|arc4random|kSecAttrAccessibleAlways)/i,
  "sql/webview":
    /(sqlite3_exec|sqlite3_prepare|SELECT .* FROM|UIWebView|evaluateJavaScript|allowFileAccess|loadFileURL)/i,
  "storage/paths":
    /(NSUserDefaults|NSFileProtectionNone|\/var\/mobile|\/Documents\/|\.sqlite|\.plist|Keychain|SecItem)/i,
  "apis/selectors":
    /(_system|strcpy|strcat|sprintf|memcpy|NSLog|UIPasteboard|jailbr|cydia|\/bin\/|\/Applications\/|fopen)/i,
};

function bucketStrings(all: string): string {
  const lines = all.split("\n");
  const parts: string[] = [];
  for (const [name, pat] of Object.entries(IOS_STRING_BUCKETS)) {
    const hits = Array.from(new Set(lines.filter((l) => pat.test(l)))).slice(0, 150);
    if (hits.length) parts.push(`## strings: ${name}\n${hits.join("\n")}`);
  }
  return parts.join("\n\n");
}

/** Runs a command, swallowing E2B's non-zero-exit throw into a normal result (fixed pipeline continues). */
async function safeRun(
  sandbox: SandboxLike,
  cmd: string,
  timeoutMs: number,
): Promise<CommandResultLike> {
  try {
    return await sandbox.commands.run(cmd, { timeoutMs, requestTimeoutMs: timeoutMs });
  } catch (err) {
    const e = err as Partial<CommandResultLike>;
    return { exitCode: e.exitCode ?? 1, stdout: e.stdout ?? "", stderr: e.stderr ?? "" };
  }
}

async function readSafe(sandbox: SandboxLike, path: string): Promise<string> {
  try {
    const c = await sandbox.files.read(path);
    return typeof c === "string" ? c : String(c ?? "");
  } catch {
    return "";
  }
}

/**
 * Deterministically unpacks an .ipa and extracts the review artifacts (Info.plist,
 * Mach-O posture, bucketed strings), returning a context block for the model, or
 * null if the unpack produced nothing to review. Streams progress to `emit`.
 */
async function extractIpaContext(
  sandbox: SandboxLike,
  remotePath: string,
  timeoutMs: number,
  emit: (s: string) => void,
): Promise<string | null> {
  const toolTimeout = Math.min(timeoutMs, 10 * 60_000);
  emit("\n$ (iOS) installing unzip + binutils + macholib\n");
  await safeRun(
    sandbox,
    "sudo apt-get update -qq && sudo apt-get install -y -qq unzip binutils python3 python3-pip",
    toolTimeout,
  );
  await safeRun(
    sandbox,
    "pip3 install -q --break-system-packages macholib 2>/dev/null || pip3 install -q macholib",
    Math.min(timeoutMs, 5 * 60_000),
  );
  emit("\n$ (iOS) unzip IPA + parse Info.plist / Mach-O\n");
  await safeRun(
    sandbox,
    `rm -rf /tmp/out && mkdir -p /tmp/out && unzip -q -o '${remotePath}' -d /tmp/out`,
    timeoutMs,
  );
  await sandbox.files.write("/tmp/ios_analyze.py", IOS_ANALYZE_PY);
  const analyze = await safeRun(sandbox, "python3 /tmp/ios_analyze.py", timeoutMs);
  const lines = (analyze.stdout || "").trim().split("\n");
  const exe = lines[0]?.trim() || "";
  const encrypted = lines.includes("ENCRYPTED");

  const infoPlist = await readSafe(sandbox, "/tmp/ios/Info.plist.xml");
  const posture = await readSafe(sandbox, "/tmp/ios/posture.json");
  const meta = await readSafe(sandbox, "/tmp/ios/meta.json");
  if (!infoPlist && !meta && !exe) return null; // nothing extracted — let the model try autonomously

  emit("\n$ (iOS) strings on the main binary\n");
  if (exe) {
    await safeRun(sandbox, `strings -a -n 6 '${exe}' > /tmp/ios/strings.txt 2>/dev/null || true`, timeoutMs);
  }
  const allStrings = await readSafe(sandbox, "/tmp/ios/strings.txt");
  const buckets = bucketStrings(allStrings);

  return [
    `Binary FairPlay-encrypted: ${encrypted}${encrypted ? " (strings/symbols will be limited)" : ""}`,
    meta && `## Info.plist summary (ATS / URL schemes / permissions)\n${meta.slice(0, 4000)}`,
    posture && `## Mach-O posture (PIE / encryption / linked dylibs)\n${posture.slice(0, 4000)}`,
    infoPlist && `## Info.plist (full)\n${infoPlist.slice(0, 12000)}`,
    buckets && `# Interesting strings & symbol/selector names from the binary\n${buckets.slice(0, 20000)}`,
  ]
    .filter(Boolean)
    .join("\n\n");
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

  let reasoningAll = "";
  const trace = (s: string) => {
    if (!s) return;
    reasoningAll += s;
    emit(s);
  };

  try {
    // Stream the artifact into the VM — a Blob reads from disk lazily, so a
    // large upload is not buffered in the worker's memory.
    const blob = await fs.openAsBlob(localArtifactPath);
    await sandbox.files.write(remotePath, blob);

    // iOS: deterministic extraction up front (the model can't guess Mach-O tools
    // on Linux). Android and everything else stay fully autonomous.
    let userContent = `Review ${remotePath} and report the security findings. Call report_finding for each confirmed issue as you verify it, then end with the final findings JSON.`;
    if (artifactName.toLowerCase().endsWith(".ipa")) {
      const iosContext = await extractIpaContext(sandbox, remotePath, cfg.cmdTimeoutMs, trace);
      if (iosContext) {
        userContent =
          `An iOS .ipa (${remotePath}) has been extracted for you in the sandbox. iOS static review on ` +
          `Linux is config/metadata/strings level (no decompiler) — that is expected, not a failure. ` +
          `Review the extracted artifacts below and call report_finding for EACH confirmed issue; use a ` +
          `file path like "Info.plist" or the binary's name so the finding attaches to the app. You may ` +
          `read more under /tmp/ios and /tmp/out with read_file/run_command. Finish with the final ` +
          `findings JSON.\n\n${iosContext}`;
      }
    }

    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: "system", content: agentScanSystemPrompt(remotePath) },
      { role: "user", content: userContent },
    ];

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
