/**
 * The flag-only contract: web corroboration may strengthen a finding but must
 * never remove or downgrade one, because search results are attacker-influenceable.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const analyzeWithLlm = vi.fn();

vi.mock("@/lib/llm-gateway", () => ({
  createLlmClient: vi.fn(() => ({ type: "openai", client: {}, model: "test" })),
  analyzeWithLlm: (...args: unknown[]) => analyzeWithLlm(...args),
  parseLlmJsonResponse: (raw: string, fallback: unknown) => {
    try {
      return JSON.parse(raw);
    } catch {
      return fallback;
    }
  },
}));

// A dependency file is required for the scanner to do anything at all.
vi.mock("./index", () => ({
  parseDependencies: () => ({
    dependencies: [
      {
        name: "evilpkg",
        version: "1.0.0",
        ecosystem: "npm",
        sourceFile: "package.json",
      },
    ],
    parsedFiles: ["package.json"],
  }),
}));

const researchPackage = vi.fn();

vi.mock("@/lib/web-research", () => ({
  researchPackage: (...args: unknown[]) => researchPackage(...args),
  formatResearchEvidence: () => "evidence block",
  // Mirrors the real call-time check, so the kill switch is exercised here too.
  isWebResearchEnabled: () =>
    process.env.ENABLE_WEB_RESEARCH !== "false" && !!process.env.TAVILY_API_KEY,
}));

const { maliciousPkgScanner } = await import("./malicious-pkg");

const ctx = {
  workDir: "/tmp/nope",
  fileList: [],
  scaFileList: [],
  scanType: "SCA_ONLY",
  orgSettings: {
    llmProvider: "openai",
    llmBaseUrl: "",
    llmModel: "test",
    enableLlmSast: true,
    enableLlmSecrets: false,
    osvApiUrl: "https://osv.invalid",
    vulnDbMode: "online" as const,
  },
};

/** The typosquat pass emits one finding for evilpkg; everything else no-ops. */
function mockTyposquatThenCorroboration(corroboration: unknown) {
  analyzeWithLlm.mockImplementation(async (_c, _m, systemPrompt: string) => {
    if (systemPrompt.includes("UNTRUSTED CONTENT") && systemPrompt.includes("corroborate")) {
      return JSON.stringify(corroboration);
    }
    if (systemPrompt.includes("TYPOSQUATTING")) {
      return JSON.stringify({
        findings: [
          {
            packageName: "evilpkg",
            version: "1.0.0",
            type: "TYPOSQUAT",
            severity: "HIGH",
            similarTo: "evilpkgs",
            description: "looks like evilpkgs",
            confidence: 0.9,
          },
        ],
      });
    }
    return JSON.stringify({ findings: [] });
  });
}

beforeEach(() => {
  analyzeWithLlm.mockReset();
  researchPackage.mockReset();
  process.env.ENABLE_WEB_RESEARCH = "true";
  // isWebResearchEnabled() requires a key, so an unconfigured install never
  // reaches the network.
  process.env.TAVILY_API_KEY = "test-key";
  // Registry/OSV lookups are irrelevant here and must not hit the network.
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: false, status: 503, json: async () => ({}) })),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.ENABLE_WEB_RESEARCH;
  delete process.env.TAVILY_API_KEY;
});

describe("web corroboration", () => {
  it("raises a corroborated finding to CRITICAL and attaches references", async () => {
    researchPackage.mockResolvedValue({
      query: "q",
      provider: "stub",
      hits: [{ title: "evilpkg malware", url: "https://snyk.test/x", excerpt: "…" }],
    });
    mockTyposquatThenCorroboration({
      corroborated: true,
      confidence: 0.95,
      reason: "advisory names evilpkg exactly",
      references: ["https://snyk.test/x"],
    });

    const findings = await maliciousPkgScanner.scan(ctx as never);
    const f = findings.find((x) => x.metadata?.packageName === "evilpkg");

    expect(f?.severity).toBe("CRITICAL");
    expect(f?.metadata?.webCorroborated).toBe(true);
    expect(f?.metadata?.references).toContain("https://snyk.test/x");
  });

  it("keeps the finding unchanged when reports do not corroborate", async () => {
    researchPackage.mockResolvedValue({
      query: "q",
      provider: "stub",
      hits: [{ title: "a different package", url: "https://x.test/y", excerpt: "…" }],
    });
    mockTyposquatThenCorroboration({
      corroborated: false,
      confidence: 0.9,
      reason: "report concerns another package",
    });

    const findings = await maliciousPkgScanner.scan(ctx as never);
    const f = findings.find((x) => x.metadata?.packageName === "evilpkg");

    // Not removed, not downgraded — search cannot clear a finding.
    expect(f).toBeDefined();
    expect(f?.severity).toBe("HIGH");
    expect(f?.metadata?.webCorroborated).toBeUndefined();
  });

  it("keeps the finding when no reports name the package", async () => {
    researchPackage.mockResolvedValue({ query: "q", provider: "stub", hits: [] });
    mockTyposquatThenCorroboration({ corroborated: false });

    const findings = await maliciousPkgScanner.scan(ctx as never);
    expect(findings.find((x) => x.metadata?.packageName === "evilpkg")).toBeDefined();
  });

  it("keeps the finding when research is unavailable", async () => {
    researchPackage.mockResolvedValue(null);
    mockTyposquatThenCorroboration({ corroborated: false });

    const findings = await maliciousPkgScanner.scan(ctx as never);
    expect(findings.find((x) => x.metadata?.packageName === "evilpkg")).toBeDefined();
  });

  it("keeps the finding when corroboration throws", async () => {
    researchPackage.mockRejectedValue(new Error("network"));
    mockTyposquatThenCorroboration({ corroborated: false });

    const findings = await maliciousPkgScanner.scan(ctx as never);
    expect(findings.find((x) => x.metadata?.packageName === "evilpkg")).toBeDefined();
  });

  it("ignores a low-confidence corroboration claim", async () => {
    researchPackage.mockResolvedValue({
      query: "q",
      provider: "stub",
      hits: [{ title: "maybe evilpkg", url: "https://x.test/y", excerpt: "…" }],
    });
    mockTyposquatThenCorroboration({ corroborated: true, confidence: 0.4 });

    const findings = await maliciousPkgScanner.scan(ctx as never);
    const f = findings.find((x) => x.metadata?.packageName === "evilpkg");
    expect(f?.severity).toBe("HIGH");
  });

  it("does not search at all when research is disabled", async () => {
    process.env.ENABLE_WEB_RESEARCH = "false";
    mockTyposquatThenCorroboration({ corroborated: false });

    await maliciousPkgScanner.scan(ctx as never);
    expect(researchPackage).not.toHaveBeenCalled();
  });

  it("does not search when the vulnerability database is offline", async () => {
    mockTyposquatThenCorroboration({ corroborated: false });

    await maliciousPkgScanner.scan({
      ...ctx,
      orgSettings: { ...ctx.orgSettings, vulnDbMode: "offline" as const },
    } as never);

    expect(researchPackage).not.toHaveBeenCalled();
  });
});
