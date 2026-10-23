import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { ScanContext } from "../types";

// Mock the agent loop and config so no E2B sandbox or network happens.
const { runAgentScan, agentScanConfig, warn, error } = vi.hoisted(() => ({
  runAgentScan: vi.fn(),
  agentScanConfig: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}));
vi.mock("./agent", () => ({ runAgentScan }));
vi.mock("./config", () => ({ agentScanConfig }));
vi.mock("@/lib/logger", () => ({ logger: { warn, error, info: vi.fn() } }));
vi.mock("@/lib/llm-gateway", () => ({
  parseLlmJsonResponse: (raw: string, fallback: unknown) => {
    try {
      return JSON.parse(raw);
    } catch {
      return fallback;
    }
  },
}));

import { mobileAgentScanner } from "./index";

const CFG = {
  openRouterApiKey: "sk-or-test",
  e2bApiKey: "e2b-test",
  model: "z-ai/glm-5.3",
  baseUrl: "https://openrouter.ai/api/v1",
  keySource: "org" as const,
  maxSteps: 50,
  sandboxTimeoutMs: 1_800_000,
  cmdTimeoutMs: 240_000,
};

let workDir: string;
const onReasoning = vi.fn();
const onProgress = vi.fn();
const onAgentStatus = vi.fn();
const onBatchFindings = vi.fn();

function ctx(uploadedArtifact?: string): ScanContext {
  return {
    workDir,
    fileList: [],
    scanType: "FULL",
    uploadedArtifact,
    orgSettings: {
      llmProvider: "openai",
      llmBaseUrl: "",
      llmModel: "",
      enableLlmSast: true,
      enableLlmSecrets: false,
      osvApiUrl: "",
      vulnDbMode: "offline",
    },
    onReasoning,
    onProgress,
    onAgentStatus,
    onBatchFindings,
  };
}

function run(content: string, reasoning = "", finished = true) {
  return { content, reasoning, steps: 2, finished };
}

beforeEach(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-scan-test-"));
  runAgentScan.mockReset();
  agentScanConfig.mockReset();
  onReasoning.mockReset();
  onProgress.mockReset();
  onAgentStatus.mockReset();
  onBatchFindings.mockReset();
  warn.mockReset();
  error.mockReset();
});

afterEach(() => {
  fs.rmSync(workDir, { recursive: true, force: true });
});

describe("mobileAgentScanner", () => {
  it("no-ops when there is no uploaded artifact (source/repo scan)", async () => {
    const out = await mobileAgentScanner.scan(ctx(undefined));
    expect(out).toEqual([]);
    expect(agentScanConfig).not.toHaveBeenCalled();
    expect(runAgentScan).not.toHaveBeenCalled();
  });

  it("no-ops when the uploaded artifact is not a binary (e.g. a source zip)", async () => {
    const out = await mobileAgentScanner.scan(ctx("project.zip"));
    expect(out).toEqual([]);
    expect(agentScanConfig).not.toHaveBeenCalled();
    expect(runAgentScan).not.toHaveBeenCalled();
  });

  it("no-ops when a binary is uploaded but the agent is not configured", async () => {
    agentScanConfig.mockReturnValue(null);
    const out = await mobileAgentScanner.scan(ctx("app.apk"));
    expect(out).toEqual([]);
    expect(runAgentScan).not.toHaveBeenCalled();
  });

  it.each(["app.apk", "bundle.aab", "MyApp.ipa", "service.jar", "app.war", "lib.dll", "tool.exe", "classes.dex"])(
    "runs for binary upload %s",
    async (artifact) => {
      agentScanConfig.mockReturnValue(CFG);
      runAgentScan.mockResolvedValue(run(JSON.stringify({ findings: [] })));
      const out = await mobileAgentScanner.scan(ctx(artifact));
      expect(out).toEqual([]);
      expect(runAgentScan).toHaveBeenCalledOnce();
      expect(runAgentScan.mock.calls[0][0]).toBe(path.join(workDir, artifact));
      expect(runAgentScan.mock.calls[0][1]).toBe(artifact);
      // key resolution is org-aware: the scanner hands config the org settings
      expect(agentScanConfig).toHaveBeenCalledWith(
        expect.objectContaining({ llmProvider: "openai" }),
      );
    },
  );

  it("maps agent findings onto RawFinding, scopes filePath to the artifact, reports status", async () => {
    agentScanConfig.mockReturnValue(CFG);
    runAgentScan.mockImplementation(
      async (
        _p: string,
        _n: string,
        _c: unknown,
        opts: { onReasoning?: (d: string) => void; onSandbox?: (id?: string) => void },
      ) => {
        opts.onSandbox?.("sbx_123");
        opts.onReasoning?.("decompiled the jar with vineflower.");
        return run(
          JSON.stringify({
            findings: [
              {
                title: "Hardcoded AES key",
                severity: "high",
                confidence: 0.8,
                category: "CWE-321",
                cweId: "CWE-321",
                filePath: "com/example/Crypto.java",
                evidence: 'SecretKeySpec("hardcoded")',
                impact: "Key recoverable from the artifact.",
                remediation: "Derive keys at runtime from a secure store.",
              },
            ],
          }),
          "decompiled the jar with vineflower.",
        );
      },
    );

    const out = await mobileAgentScanner.scan(ctx("service.jar"));
    expect(out).toHaveLength(1);
    const f = out[0];
    expect(f.scanner).toBe("SAST_LLM");
    expect(f.severity).toBe("HIGH");
    expect(f.cweId).toBe("CWE-321");
    expect(f.ruleId).toBe("agent/cwe-321");
    expect(f.confidence).toBe(0.8);
    expect(f.filePath).toBe("service.jar!/com/example/Crypto.java");
    expect(f.metadata?.remediation).toContain("secure store");
    expect(f.metadata?.scanner).toBe("agent-scan");
    // reasoning persisted via the sink
    expect(onReasoning).toHaveBeenCalledWith("agent-scan", expect.stringContaining("vineflower"));
    // visible status: running (with sandbox id) then completed
    expect(onAgentStatus).toHaveBeenCalledWith(
      expect.objectContaining({ status: "RUNNING", sandboxId: "sbx_123" }),
    );
    expect(onAgentStatus).toHaveBeenCalledWith(
      expect.objectContaining({ status: "DONE", outcome: "completed", reported: 1 }),
    );
  });

  it("streams report_finding findings into onBatchFindings immediately (live Findings tab)", async () => {
    agentScanConfig.mockReturnValue(CFG);
    runAgentScan.mockImplementation(
      async (
        _p: string,
        _n: string,
        _c: unknown,
        opts: { onFinding?: (f: unknown) => Promise<void> | void },
      ) => {
        await opts.onFinding?.({
          title: "Cleartext HTTP",
          severity: "HIGH",
          file: "com/example/Net.java",
          line: 42,
          vulnerability: "Uses http:// for login",
          attack: "MITM can read credentials",
          fix: "Use https and enable network-security-config",
          confidence: "high",
          cwe: "CWE-319",
        });
        // nothing in the final JSON — it was all streamed
        return run(JSON.stringify({ findings: [] }));
      },
    );

    const out = await mobileAgentScanner.scan(ctx("app.apk"));
    // inserted live, before the scan returned
    expect(onBatchFindings).toHaveBeenCalledTimes(1);
    const [scannerName, batch] = onBatchFindings.mock.calls[0];
    expect(scannerName).toBe("agent-scan");
    expect(batch).toHaveLength(1);
    const f = batch[0];
    expect(f.scanner).toBe("SAST_LLM");
    expect(f.severity).toBe("HIGH");
    expect(f.filePath).toBe("app.apk!/com/example/Net.java");
    expect(f.startLine).toBe(42);
    expect(f.cweId).toBe("CWE-319");
    expect(f.confidence).toBe(0.9);
    expect(f.description).toContain("Attack: MITM");
    expect(f.description).toContain("Fix: Use https");
    // and it is also returned so the dedup/complete path sees it
    expect(out).toHaveLength(1);
    expect(out[0].title).toBe("Cleartext HTTP");
  });

  it("returns streamed + final-JSON findings; the distinct count de-dupes overlap", async () => {
    agentScanConfig.mockReturnValue(CFG);
    runAgentScan.mockImplementation(
      async (
        _p: string,
        _n: string,
        _c: unknown,
        opts: { onFinding?: (f: unknown) => Promise<void> | void },
      ) => {
        await opts.onFinding?.({
          title: "Hardcoded key",
          severity: "HIGH",
          file: "com/example/Crypto.java",
          vulnerability: "Static AES key",
          fix: "Derive at runtime",
          confidence: "medium",
        });
        // final JSON repeats the streamed one (same file+title) and adds a new one
        return run(
          JSON.stringify({
            findings: [
              { title: "Hardcoded key", severity: "HIGH", filePath: "com/example/Crypto.java" },
              { title: "Debuggable enabled", severity: "LOW", filePath: "AndroidManifest.xml" },
            ],
          }),
        );
      },
    );

    const out = await mobileAgentScanner.scan(ctx("app.apk"));
    // returns everything (downstream FindingDeduplicator drops the repeat)
    expect(out).toHaveLength(3);
    // but the reported status count is de-duped by file+title
    expect(onAgentStatus).toHaveBeenCalledWith(
      expect.objectContaining({ status: "DONE", outcome: "completed", reported: 2 }),
    );
    // the streamed one was inserted live
    expect(onBatchFindings).toHaveBeenCalledTimes(1);
  });

  it("falls back filePath to the artifact name, normalizes severity, clamps confidence", async () => {
    agentScanConfig.mockReturnValue(CFG);
    runAgentScan.mockResolvedValue(
      run(JSON.stringify({ findings: [{ title: "Odd", severity: "spicy", confidence: 9 }] })),
    );
    const out = await mobileAgentScanner.scan(ctx("app.apk"));
    expect(out[0].severity).toBe("MEDIUM");
    expect(out[0].confidence).toBe(1);
    expect(out[0].filePath).toBe("app.apk");
  });

  it("marks the status incomplete when the agent stopped at the step/time limit", async () => {
    agentScanConfig.mockReturnValue(CFG);
    runAgentScan.mockResolvedValue(
      run(JSON.stringify({ findings: [{ title: "Partial" }] }), "", false),
    );
    await mobileAgentScanner.scan(ctx("app.apk"));
    expect(onAgentStatus).toHaveBeenCalledWith(
      expect.objectContaining({ status: "DONE", outcome: "incomplete" }),
    );
  });

  it("drops findings without a title", async () => {
    agentScanConfig.mockReturnValue(CFG);
    runAgentScan.mockResolvedValue(
      run(JSON.stringify({ findings: [{ severity: "HIGH" }, { title: "Keep" }] })),
    );
    const out = await mobileAgentScanner.scan(ctx("app.apk"));
    expect(out).toHaveLength(1);
    expect(out[0].title).toBe("Keep");
  });

  it("returns [] and reports a failed status when the agent run throws", async () => {
    agentScanConfig.mockReturnValue(CFG);
    runAgentScan.mockRejectedValue(new Error("e2b exploded"));
    const out = await mobileAgentScanner.scan(ctx("app.apk"));
    expect(out).toEqual([]);
    expect(error).toHaveBeenCalled();
    expect(onAgentStatus).toHaveBeenCalledWith(
      expect.objectContaining({ status: "DONE", outcome: "failed" }),
    );
  });
});
