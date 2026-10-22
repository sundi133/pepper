import fs from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AI_MOBILE_REVIEW_RULE_PREFIX,
  AiMobileReviewError,
  aiMobileReviewAccess,
  aiMobileReviewConfig,
  aiMobileReviewInstructions,
  findJadxJar,
  isAiMobileReviewFinding,
  normalizeInnerPath,
  parseAiMobileReviewAnswer,
  runAiMobileReview,
  toRawFindings,
  type AiMobileReviewClient,
  type AiMobileReviewConfig,
} from "./mobile-ai-review";
import { mobilePlatformOf } from "./mobile-platform";

const answer = {
  findings: [
    {
      title: "Exported content provider leaks notes",
      severity: "HIGH",
      file: "/mnt/data/decompiled/resources/AndroidManifest.xml",
      line: 42,
      cwe: "CWE-926",
      description: "NoteProvider is exported without a permission.",
      evidence: '<provider android:name=".NoteProvider" android:exported="true" />',
      exploitation: "Any app can query content://notes.",
      recommendation: "Set android:exported=false or require a signature permission.",
      confidence: 0.9,
    },
    {
      title: "Hardcoded API key",
      severity: "MEDIUM",
      file: "sources/com/example/Api.java",
      line: null,
      cwe: "798",
      description: "A live key is in the code.",
      evidence: 'String KEY = "sk_live_...";',
      exploitation: "",
      recommendation: "",
      confidence: 1.4,
    },
  ],
  notInspected: "Native libraries in lib/.",
};

describe("mobilePlatformOf", () => {
  it("maps app files to their platform", () => {
    expect(mobilePlatformOf("allsafe.apk")).toBe("android");
    expect(mobilePlatformOf("Bundle.AAB")).toBe("android");
    expect(mobilePlatformOf("MyApp.ipa")).toBe("ios");
  });

  it("ignores everything else", () => {
    for (const name of ["app.jar", "source.zip", "ipa", "app.apk.zip", "", null, undefined]) {
      expect(mobilePlatformOf(name)).toBeNull();
    }
  });
});

describe("aiMobileReviewAccess", () => {
  const NO_ENV = {}; // force the org-config fallback path

  it("uses a stored key regardless of the org provider (dedicated, then OPENAI_API_KEY)", () => {
    // Org is OpenRouter, but a dedicated mobile key is set → mobile still runs.
    expect(
      aiMobileReviewAccess(
        { llmProvider: "openrouter", llmApiKey: "orgkey" },
        { MOBILE_AI_REVIEW_API_KEY: " sk-mobile " },
      ),
    ).toEqual({ ok: true, apiKey: "sk-mobile", baseURL: "https://api.openai.com/v1" });
    // Falls back to OPENAI_API_KEY.
    expect(
      aiMobileReviewAccess({ llmProvider: "openrouter" }, { OPENAI_API_KEY: "sk-openai" }),
    ).toMatchObject({ ok: true, apiKey: "sk-openai" });
    // A stored key on a non-OpenAI host is refused (hosted shell is OpenAI-only).
    expect(
      aiMobileReviewAccess({}, { MOBILE_AI_REVIEW_API_KEY: "k", MOBILE_AI_REVIEW_BASE_URL: "https://proxy.example.com/v1" }).ok,
    ).toBe(false);
  });

  it("accepts an OpenAI key on api.openai.com (org fallback)", () => {
    expect(aiMobileReviewAccess({ llmProvider: "openai", llmBaseUrl: "https://api.openai.com/v1", llmApiKey: " sk-1 " }, NO_ENV)).toEqual({
      ok: true,
      apiKey: "sk-1",
      baseURL: "https://api.openai.com/v1",
    });
    expect(aiMobileReviewAccess({ llmProvider: "OpenAI", llmBaseUrl: "", llmApiKey: "sk-1" }, NO_ENV)).toMatchObject({ ok: true });
  });

  it("refuses other providers, missing keys and other hosts (no stored key)", () => {
    expect(aiMobileReviewAccess({ llmProvider: "openrouter", llmBaseUrl: "https://openrouter.ai/api/v1", llmApiKey: "k" }, NO_ENV).ok).toBe(false);
    expect(aiMobileReviewAccess({ llmProvider: "openai", llmBaseUrl: "https://api.openai.com/v1", llmApiKey: "" }, NO_ENV).ok).toBe(false);
    expect(aiMobileReviewAccess({ llmProvider: "openai", llmBaseUrl: "https://proxy.example.com/v1", llmApiKey: "k" }, NO_ENV)).toMatchObject({
      ok: false,
      reason: expect.stringContaining("proxy.example.com"),
    });
    expect(aiMobileReviewAccess({ llmProvider: "openai", llmBaseUrl: "not a url", llmApiKey: "k" }, NO_ENV).ok).toBe(false);
  });
});

describe("aiMobileReviewConfig", () => {
  it("defaults to gpt-6-astra, high effort, 30 minutes, 50 findings", () => {
    expect(aiMobileReviewConfig({})).toEqual({
      model: "gpt-6-astra",
      effort: "high",
      timeoutMs: 30 * 60_000,
      maxFindings: 50,
      jadxJar: null,
    });
  });

  it("reads the environment and ignores invalid values", () => {
    expect(
      aiMobileReviewConfig({
        MOBILE_AI_REVIEW_MODEL: "gpt-6-astra-2026-10-01",
        MOBILE_AI_REVIEW_EFFORT: "XHIGH",
        MOBILE_AI_REVIEW_TIMEOUT_MINUTES: "45",
        MOBILE_AI_REVIEW_MAX_FINDINGS: "10",
        MOBILE_AI_REVIEW_JADX_JAR: "/opt/jadx/lib/jadx.jar",
      }),
    ).toEqual({ model: "gpt-6-astra-2026-10-01", effort: "xhigh", timeoutMs: 45 * 60_000, maxFindings: 10, jadxJar: "/opt/jadx/lib/jadx.jar" });
    expect(aiMobileReviewConfig({ MOBILE_AI_REVIEW_EFFORT: "turbo", MOBILE_AI_REVIEW_TIMEOUT_MINUTES: "-3" })).toMatchObject({
      effort: "high",
      timeoutMs: 30 * 60_000,
    });
  });
});

describe("findJadxJar", () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "jadx-"));
    fs.mkdirSync(path.join(dir, "jadx", "bin"), { recursive: true });
    fs.mkdirSync(path.join(dir, "jadx", "lib"));
    fs.writeFileSync(path.join(dir, "jadx", "bin", "jadx"), "#!/bin/sh\n");
    fs.writeFileSync(path.join(dir, "jadx", "lib", "jadx-1.5.6-all.jar"), "");
    fs.mkdirSync(path.join(dir, "bin"));
    fs.symlinkSync(path.join(dir, "jadx", "bin", "jadx"), path.join(dir, "bin", "jadx"));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("follows the launcher on PATH to the all-in-one jar", () => {
    const jar = fs.realpathSync(path.join(dir, "jadx", "lib", "jadx-1.5.6-all.jar"));
    expect(findJadxJar("jadx", { PATH: `/nonexistent${path.delimiter}${path.join(dir, "bin")}` })).toBe(jar);
    expect(findJadxJar(path.join(dir, "bin", "jadx"), {})).toBe(jar);
  });

  it("returns null when jadx is not installed", () => {
    expect(findJadxJar("jadx", { PATH: "/nonexistent" })).toBeNull();
  });
});

describe("aiMobileReviewInstructions", () => {
  it("gives Android apps Android checks and the jadx command", () => {
    const text = aiMobileReviewInstructions("android", "allsafe.apk", true);
    expect(text).toContain("Android application security reviewer");
    expect(text).toContain("/mnt/data/allsafe.apk");
    expect(text).toContain("jadx.cli.JadxCLI");
    expect(text).toContain("network_security_config");
    expect(text).not.toContain("Info.plist");
  });

  it("falls back to Python for Android without jadx", () => {
    const text = aiMobileReviewInstructions("android", "app.apk", false);
    expect(text).not.toContain("jadx.jar");
    expect(text).toContain("No decompiler is provided");
  });

  it("gives iOS apps iOS checks", () => {
    const text = aiMobileReviewInstructions("ios", "MyApp.ipa", false);
    expect(text).toContain("iOS application security reviewer");
    expect(text).toContain("/mnt/data/MyApp.ipa");
    expect(text).toContain("NSAppTransportSecurity");
    expect(text).toContain("cryptid");
    expect(text).not.toContain("AndroidManifest");
  });

  it("tells the model the app's content is untrusted", () => {
    for (const p of ["android", "ios"] as const) {
      expect(aiMobileReviewInstructions(p, "x", false)).toContain("untrusted data");
    }
  });
});

describe("answer parsing and findings", () => {
  it("normalizes paths reported inside the container", () => {
    expect(normalizeInnerPath("/mnt/data/decompiled/sources/a/B.java")).toBe("sources/a/B.java");
    expect(normalizeInnerPath("extracted/Payload/X.app/Info.plist")).toBe("Payload/X.app/Info.plist");
    expect(normalizeInnerPath("./resources\\AndroidManifest.xml")).toBe("resources/AndroidManifest.xml");
  });

  it("turns the answer into SAST_LLM findings against app!/file", () => {
    const findings = toRawFindings(parseAiMobileReviewAnswer(JSON.stringify(answer)), {
      appName: "allsafe.apk",
      platform: "android",
      model: "gpt-6-astra",
      maxFindings: 50,
    });
    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({
      scanner: "SAST_LLM",
      severity: "HIGH",
      filePath: "allsafe.apk!/resources/AndroidManifest.xml",
      startLine: 42,
      cweId: "CWE-926",
      confidence: 0.9,
      ruleId: `${AI_MOBILE_REVIEW_RULE_PREFIX}exported-content-provider-leaks-notes`,
      metadata: { aiMobileReview: true, platform: "android", model: "gpt-6-astra", decompiledFrom: "allsafe.apk" },
    });
    expect(findings[0].description).toContain("How it can be exploited: Any app can query");
    expect(findings[0].description).toContain("Fix: Set android:exported=false");
    expect(findings[0].snippet).toContain("NoteProvider");
    expect(findings[1]).toMatchObject({ cweId: "CWE-798", startLine: undefined, confidence: 1 });
    expect(findings[1].description).toBe("A live key is in the code.");
    expect(findings.every(isAiMobileReviewFinding)).toBe(true);
    expect(isAiMobileReviewFinding({ ruleId: null })).toBe(false);
  });

  it("caps the number of findings", () => {
    const findings = toRawFindings(parseAiMobileReviewAnswer(JSON.stringify(answer)), {
      appName: "a.apk",
      platform: "android",
      model: "m",
      maxFindings: 1,
    });
    expect(findings).toHaveLength(1);
  });

  it("rejects answers that are not the findings JSON", () => {
    expect(() => parseAiMobileReviewAnswer("I found three issues")).toThrow(/not valid JSON/);
    expect(() => parseAiMobileReviewAnswer(JSON.stringify({ findings: [{ title: "x" }] }))).toThrow(/schema/);
    expect(() =>
      parseAiMobileReviewAnswer(JSON.stringify({ ...answer, findings: [{ ...answer.findings[0], severity: "SEVERE" }] })),
    ).toThrow(/schema/);
  });
});

describe("runAiMobileReview", () => {
  let dir: string;
  let appPath: string;
  let jarPath: string;
  const config: AiMobileReviewConfig = {
    model: "gpt-6-astra",
    effort: "high",
    timeoutMs: 60_000,
    maxFindings: 50,
    jadxJar: null,
  };

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "ai-review-"));
    appPath = path.join(dir, "allsafe.apk");
    jarPath = path.join(dir, "jadx-1.5.6-all.jar");
    fs.writeFileSync(appPath, "PK fake apk");
    fs.writeFileSync(jarPath, "PK fake jar");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  function fakeClient(responses: Array<Record<string, unknown>>) {
    const queue = [...responses];
    const uploaded: string[] = [];
    const client = {
      containers: {
        create: vi.fn(async () => ({ id: "cntr_1" })),
        delete: vi.fn(async () => undefined),
        files: {
          create: vi.fn(async (_id: string, body: { file: { name: string } }) => {
            uploaded.push(body.file.name);
            return { id: `file_${uploaded.length}` };
          }),
        },
      },
      responses: {
        create: vi.fn<(body: { instructions: string } & Record<string, unknown>) => Promise<unknown>>(
          async () => queue.shift(),
        ),
        retrieve: vi.fn(async () => queue.shift()),
        cancel: vi.fn(async () => ({})),
      },
    };
    return { client, uploaded, typed: client as unknown as AiMobileReviewClient };
  }

  const completed = {
    id: "resp_1",
    status: "completed",
    output_text: JSON.stringify(answer),
    usage: { input_tokens: 120_000, output_tokens: 9_000 },
  };

  it("uploads the app and jadx, asks with the shell tool, and returns findings", async () => {
    const { client, uploaded, typed } = fakeClient([{ id: "resp_1", status: "queued" }, { id: "resp_1", status: "in_progress" }, completed]);
    const outcome = await runAiMobileReview({
      scanId: "scan1",
      appPath,
      appName: "allsafe.apk",
      platform: "android",
      access: { apiKey: "k", baseURL: "https://api.openai.com/v1" },
      config: { ...config, jadxJar: jarPath },
      client: typed,
      pollIntervalMs: 1,
    });

    expect(client.containers.create).toHaveBeenCalledWith(
      expect.objectContaining({ name: "pepper-scan-scan1", memory_limit: "4g" }),
    );
    // No network policy: the container cannot reach the internet.
    expect(client.containers.create.mock.calls[0]).not.toEqual(
      expect.arrayContaining([expect.objectContaining({ network_policy: expect.anything() })]),
    );
    expect(uploaded).toEqual(["allsafe.apk", "jadx.jar"]);
    const request = client.responses.create.mock.calls[0][0];
    expect(request).toMatchObject({
      model: "gpt-6-astra",
      background: true,
      reasoning: { effort: "high" },
      tools: [{ type: "shell", environment: { type: "container_reference", container_id: "cntr_1" } }],
      text: { format: { type: "json_schema", strict: true } },
    });
    expect(request.instructions).toContain("jadx.cli.JadxCLI");
    expect(client.responses.retrieve).toHaveBeenCalledTimes(2);
    expect(outcome.findings).toHaveLength(2);
    expect(outcome.summary).toMatchObject({
      platform: "android",
      model: "gpt-6-astra",
      findings: 2,
      decompiler: "jadx",
      inputTokens: 120_000,
      outputTokens: 9_000,
      notInspected: "Native libraries in lib/.",
    });
    expect(client.containers.delete).toHaveBeenCalledWith("cntr_1");
  });

  it("does not upload jadx for an iOS app", async () => {
    const { uploaded, typed, client } = fakeClient([completed]);
    const outcome = await runAiMobileReview({
      scanId: "s",
      appPath,
      appName: "MyApp.ipa",
      platform: "ios",
      access: { apiKey: "k", baseURL: "https://api.openai.com/v1" },
      config: { ...config, jadxJar: jarPath },
      client: typed,
    });
    expect(uploaded).toEqual(["MyApp.ipa"]);
    expect(client.responses.create.mock.calls[0][0].instructions).toContain("iOS application");
    expect(outcome.summary.decompiler).toBeNull();
  });

  it("deletes the container when the model fails", async () => {
    const { client, typed } = fakeClient([{ id: "r", status: "failed", error: { message: "rate limited" } }]);
    await expect(
      runAiMobileReview({
        scanId: "s",
        appPath,
        appName: "allsafe.apk",
        platform: "android",
        access: { apiKey: "k", baseURL: "u" },
        config,
        client: typed,
      }),
    ).rejects.toThrow(/rate limited/);
    expect(client.containers.delete).toHaveBeenCalledWith("cntr_1");
  });

  it("cancels the response and gives up after the timeout", async () => {
    let t = 0;
    const { client, typed } = fakeClient(Array.from({ length: 10 }, () => ({ id: "r", status: "in_progress" })));
    const error = await runAiMobileReview({
      scanId: "s",
      appPath,
      appName: "allsafe.apk",
      platform: "android",
      access: { apiKey: "k", baseURL: "u" },
      config: { ...config, timeoutMs: 25 },
      client: typed,
      pollIntervalMs: 1,
      now: () => (t += 10),
    }).catch((e) => e);
    expect(error).toBeInstanceOf(AiMobileReviewError);
    expect((error as AiMobileReviewError).kind).toBe("timeout");
    expect(client.responses.cancel).toHaveBeenCalledWith("r");
    expect(client.containers.delete).toHaveBeenCalled();
  });

  it("cancels the response when the scan is cancelled", async () => {
    const controller = new AbortController();
    const { client, typed } = fakeClient(Array.from({ length: 10 }, () => ({ id: "r", status: "in_progress" })));
    const run = runAiMobileReview({
      scanId: "s",
      appPath,
      appName: "allsafe.apk",
      platform: "android",
      access: { apiKey: "k", baseURL: "u" },
      config,
      client: typed,
      signal: controller.signal,
      pollIntervalMs: 50,
    });
    setTimeout(() => controller.abort(new Error("scan cancelled")), 5);
    await expect(run).rejects.toThrow(/scan cancelled/);
    expect(client.responses.cancel).toHaveBeenCalledWith("r");
    expect(client.containers.delete).toHaveBeenCalled();
  });
});
