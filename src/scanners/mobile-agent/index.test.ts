import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { ScanContext } from "../types";

// Mock the agent loop and config so no E2B sandbox or network happens.
const { runMobileAgent, mobileAgentConfigFromEnv, warn, error } = vi.hoisted(
  () => ({
    runMobileAgent: vi.fn(),
    mobileAgentConfigFromEnv: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
);
vi.mock("./agent", () => ({ runMobileAgent }));
vi.mock("./config", () => ({ mobileAgentConfigFromEnv }));
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
  maxSteps: 50,
  sandboxTimeoutMs: 1_800_000,
  cmdTimeoutMs: 240_000,
};

let workDir: string;
const onReasoning = vi.fn();
const onProgress = vi.fn();

function ctx(fileList: string[]): ScanContext {
  return {
    workDir,
    fileList,
    scanType: "FULL",
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
  };
}

function run(content: string, reasoning = "") {
  return { content, reasoning, steps: 2, finished: true };
}

function writeFile(rel: string, content: string) {
  const full = path.join(workDir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
}

beforeEach(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), "mobile-agent-test-"));
  runMobileAgent.mockReset();
  mobileAgentConfigFromEnv.mockReset();
  onReasoning.mockReset();
  onProgress.mockReset();
  warn.mockReset();
  error.mockReset();
});

afterEach(() => {
  fs.rmSync(workDir, { recursive: true, force: true });
});

describe("mobileAgentScanner", () => {
  it("no-ops when the scan has no mobile artifact (non-mobile scan)", async () => {
    writeFile("src/app.ts", "const x = 1;");
    const out = await mobileAgentScanner.scan(ctx(["src/app.ts"]));
    expect(out).toEqual([]);
    expect(mobileAgentConfigFromEnv).not.toHaveBeenCalled();
    expect(runMobileAgent).not.toHaveBeenCalled();
  });

  it("no-ops when a mobile artifact exists but the mode is off / keys missing", async () => {
    writeFile("app.apk", "PK\u0003\u0004 fake");
    mobileAgentConfigFromEnv.mockReturnValue(null);
    const out = await mobileAgentScanner.scan(ctx(["app.apk"]));
    expect(out).toEqual([]);
    expect(runMobileAgent).not.toHaveBeenCalled();
  });

  it("detects the artifact from the workDir root even when it is not in fileList", async () => {
    // An uploaded compiled artifact is often filtered out of the source list.
    writeFile("app.apk", "PK\u0003\u0004 fake");
    mobileAgentConfigFromEnv.mockReturnValue(CFG);
    runMobileAgent.mockResolvedValue(run(JSON.stringify({ findings: [] })));
    const out = await mobileAgentScanner.scan(ctx([]));
    expect(out).toEqual([]);
    expect(runMobileAgent).toHaveBeenCalledOnce();
    expect(runMobileAgent.mock.calls[0][0]).toBe(path.join(workDir, "app.apk"));
    expect(runMobileAgent.mock.calls[0][1]).toBe("app.apk");
  });

  it("maps agent findings onto RawFinding and scopes filePath to the app", async () => {
    writeFile("app.apk", "PK\u0003\u0004 fake");
    mobileAgentConfigFromEnv.mockReturnValue(CFG);
    runMobileAgent.mockImplementation(
      async (
        _p: string,
        _n: string,
        _c: unknown,
        opts: { onReasoning?: (d: string) => void },
      ) => {
        opts.onReasoning?.("I installed jadx and decompiled the apk.");
        return run(
          JSON.stringify({
            findings: [
              {
                title: "Exported activity without permission",
                severity: "high",
                confidence: 0.8,
                category: "MASVS-PLATFORM",
                cweId: "CWE-926",
                filePath: "com/example/MainActivity.java",
                evidence: 'android:exported="true"',
                impact: "Any app can launch this component.",
                remediation: "Set android:exported=false or require a permission.",
              },
            ],
          }),
          "I installed jadx and decompiled the apk.",
        );
      },
    );

    const out = await mobileAgentScanner.scan(ctx(["app.apk"]));
    expect(out).toHaveLength(1);
    const f = out[0];
    expect(f.scanner).toBe("SAST_LLM");
    expect(f.severity).toBe("HIGH");
    expect(f.cweId).toBe("CWE-926");
    expect(f.ruleId).toBe("mobile-agent/masvs-platform");
    expect(f.confidence).toBe(0.8);
    expect(f.filePath).toBe("app.apk!/com/example/MainActivity.java");
    expect(f.metadata?.remediation).toContain("exported=false");
    expect(f.metadata?.scanner).toBe("mobile-agent");
    // reasoning trace was streamed and persisted via the reasoning sink
    expect(onReasoning).toHaveBeenCalledWith(
      "mobile-agent",
      "I installed jadx and decompiled the apk.",
    );
  });

  it("falls back filePath to the artifact name, normalizes severity, clamps confidence", async () => {
    writeFile("bundle.aab", "PK\u0003\u0004 fake");
    mobileAgentConfigFromEnv.mockReturnValue(CFG);
    runMobileAgent.mockResolvedValue(
      run(JSON.stringify({ findings: [{ title: "Odd", severity: "spicy", confidence: 9 }] })),
    );
    const out = await mobileAgentScanner.scan(ctx(["bundle.aab"]));
    expect(out[0].severity).toBe("MEDIUM");
    expect(out[0].confidence).toBe(1);
    expect(out[0].filePath).toBe("bundle.aab");
  });

  it("accepts an iOS .ipa upload", async () => {
    writeFile("MyApp.ipa", "PK\u0003\u0004 fake");
    mobileAgentConfigFromEnv.mockReturnValue(CFG);
    runMobileAgent.mockResolvedValue(
      run(
        JSON.stringify({
          findings: [{ title: "ATS disabled", severity: "high", cwe: "CWE-319" }],
        }),
      ),
    );
    const out = await mobileAgentScanner.scan(ctx(["MyApp.ipa"]));
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("HIGH");
    expect(out[0].cweId).toBe("CWE-319");
  });

  it("drops findings without a title", async () => {
    writeFile("app.apk", "PK\u0003\u0004 fake");
    mobileAgentConfigFromEnv.mockReturnValue(CFG);
    runMobileAgent.mockResolvedValue(
      run(JSON.stringify({ findings: [{ severity: "HIGH" }, { title: "Keep" }] })),
    );
    const out = await mobileAgentScanner.scan(ctx(["app.apk"]));
    expect(out).toHaveLength(1);
    expect(out[0].title).toBe("Keep");
  });

  it("returns [] and logs when the agent run throws", async () => {
    writeFile("app.apk", "PK\u0003\u0004 fake");
    mobileAgentConfigFromEnv.mockReturnValue(CFG);
    runMobileAgent.mockRejectedValue(new Error("e2b exploded"));
    const out = await mobileAgentScanner.scan(ctx(["app.apk"]));
    expect(out).toEqual([]);
    expect(error).toHaveBeenCalled();
  });
});
