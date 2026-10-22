import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import type { ScanContext } from "../types";

// Mock the GLM call and config so no network happens. vi.hoisted keeps these
// available to the hoisted vi.mock factories below.
const { reviewMobileBundle, mobileReviewConfigFromEnv, warn, error } = vi.hoisted(
  () => ({
    reviewMobileBundle: vi.fn(),
    mobileReviewConfigFromEnv: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  }),
);
vi.mock("./glm-review", () => ({ reviewMobileBundle, mobileReviewConfigFromEnv }));
vi.mock("@/lib/logger", () => ({ logger: { warn, error, info: vi.fn() } }));

// Keep the real markdown-stripping JSON parser behavior lightweight.
vi.mock("@/lib/llm-gateway", () => ({
  parseLlmJsonResponse: (raw: string, fallback: unknown) => {
    try {
      return JSON.parse(raw);
    } catch {
      return fallback;
    }
  },
}));

import { mobileLlmScanner } from "./index";

const CFG = { apiKey: "sk-or-test", model: "z-ai/glm-5.3", baseUrl: "https://openrouter.ai/api/v1" };

let workDir: string;

const onReasoning = vi.fn();

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
  };
}

/** Build a MobileReviewResult the streaming review would return. */
function reviewResult(content: string, reasoning = "") {
  return { content, reasoning };
}

function writeFile(rel: string, content: string) {
  const full = path.join(workDir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
}

beforeEach(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), "mobile-test-"));
  reviewMobileBundle.mockReset();
  mobileReviewConfigFromEnv.mockReset();
  onReasoning.mockReset();
  warn.mockReset();
  error.mockReset();
});

afterEach(() => {
  fs.rmSync(workDir, { recursive: true, force: true });
});

describe("mobileLlmScanner", () => {
  it("no-ops when there is no AndroidManifest (non-mobile scan)", async () => {
    writeFile("src/app.ts", "const x = 1;");
    const out = await mobileLlmScanner.scan(ctx(["src/app.ts"]));
    expect(out).toEqual([]);
    expect(mobileReviewConfigFromEnv).not.toHaveBeenCalled();
    expect(reviewMobileBundle).not.toHaveBeenCalled();
  });

  it("no-ops (and warns) when a manifest exists but no API key is configured", async () => {
    writeFile("AndroidManifest.xml", "<manifest/>");
    mobileReviewConfigFromEnv.mockReturnValue(null);
    const out = await mobileLlmScanner.scan(ctx(["AndroidManifest.xml"]));
    expect(out).toEqual([]);
    expect(reviewMobileBundle).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalled();
  });

  it("maps GLM findings onto RawFinding", async () => {
    writeFile("AndroidManifest.xml", "<manifest><application debuggable=\"true\"/></manifest>");
    writeFile("com/example/Login.java", "class Login {}");
    mobileReviewConfigFromEnv.mockReturnValue(CFG);
    reviewMobileBundle.mockResolvedValue(
      reviewResult(
        JSON.stringify({
          findings: [
            {
              title: "Application is debuggable",
              severity: "medium",
              confidence: 0.9,
              category: "MASVS-RESILIENCE",
              cwe: "CWE-489",
              filePath: "AndroidManifest.xml",
              line: 1,
              component: "application",
              description: "android:debuggable is true.",
              evidence: "debuggable=\"true\"",
              impact: "Eases inspection of a released build.",
              remediation: "Set android:debuggable to false in release builds.",
            },
          ],
        }),
        "I checked the manifest and saw debuggable=true.",
      ),
    );

    const out = await mobileLlmScanner.scan(
      ctx(["AndroidManifest.xml", "com/example/Login.java"]),
    );
    expect(out).toHaveLength(1);
    const f = out[0];
    expect(f.scanner).toBe("SAST_LLM");
    expect(f.severity).toBe("MEDIUM");
    expect(f.cweId).toBe("CWE-489");
    expect(f.ruleId).toBe("mobile/masvs-resilience");
    expect(f.confidence).toBe(0.9);
    expect(f.metadata?.remediation).toContain("release builds");
    expect(f.metadata?.affectedComponent).toBe("application");
    // the bundle it reviewed included the manifest
    expect(reviewMobileBundle).toHaveBeenCalledOnce();
    expect(reviewMobileBundle.mock.calls[0][0]).toContain("AndroidManifest.xml");
    // the reasoning trace was handed to the processor for storage
    expect(onReasoning).toHaveBeenCalledWith(
      "mobile-llm",
      "I checked the manifest and saw debuggable=true.",
    );
  });

  it("normalizes unknown severity to MEDIUM, clamps confidence, falls back filePath to the manifest", async () => {
    writeFile("AndroidManifest.xml", "<manifest/>");
    mobileReviewConfigFromEnv.mockReturnValue(CFG);
    reviewMobileBundle.mockResolvedValue(
      reviewResult(
        JSON.stringify({
          findings: [{ title: "Odd one", severity: "spicy", confidence: 5 }],
        }),
      ),
    );
    const out = await mobileLlmScanner.scan(ctx(["AndroidManifest.xml"]));
    expect(out[0].severity).toBe("MEDIUM");
    expect(out[0].confidence).toBe(1);
    expect(out[0].filePath).toBe("AndroidManifest.xml");
  });

  it("returns [] and logs when the review call throws", async () => {
    writeFile("AndroidManifest.xml", "<manifest/>");
    mobileReviewConfigFromEnv.mockReturnValue(CFG);
    reviewMobileBundle.mockRejectedValue(new Error("network"));
    const out = await mobileLlmScanner.scan(ctx(["AndroidManifest.xml"]));
    expect(out).toEqual([]);
    expect(error).toHaveBeenCalled();
  });

  it("also fires for an extracted iOS app (Info.plist anchor)", async () => {
    writeFile("Info.plist", "bplist00 NSAllowsArbitraryLoads");
    mobileReviewConfigFromEnv.mockReturnValue(CFG);
    reviewMobileBundle.mockResolvedValue(
      reviewResult(
        JSON.stringify({
          findings: [
            { title: "App Transport Security disabled", severity: "high", cwe: "CWE-319" },
          ],
        }),
      ),
    );
    const out = await mobileLlmScanner.scan(ctx(["Info.plist"]));
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("HIGH");
    expect(reviewMobileBundle).toHaveBeenCalledOnce();
  });

  it("drops findings without a title", async () => {
    writeFile("AndroidManifest.xml", "<manifest/>");
    mobileReviewConfigFromEnv.mockReturnValue(CFG);
    reviewMobileBundle.mockResolvedValue(
      reviewResult(
        JSON.stringify({ findings: [{ severity: "HIGH" }, { title: "Keep" }] }),
      ),
    );
    const out = await mobileLlmScanner.scan(ctx(["AndroidManifest.xml"]));
    expect(out).toHaveLength(1);
    expect(out[0].title).toBe("Keep");
  });
});
