import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  buildPackageQuery,
  ecosystemSearchTerms,
  mentionsPackage,
  formatResearchEvidence,
  researchPackage,
  __setSearchProvider,
  __resetSearchProvider,
  __clearWebResearchCache,
  type WebResearchHit,
} from "./web-research";

const hit = (over: Partial<WebResearchHit> = {}): WebResearchHit => ({
  title: "Example",
  url: "https://example.test/a",
  excerpt: "some text",
  ...over,
});

beforeEach(() => {
  __clearWebResearchCache();
  process.env.TAVILY_API_KEY = "test-key";
});

afterEach(() => {
  __resetSearchProvider();
  delete process.env.TAVILY_API_KEY;
  vi.restoreAllMocks();
});

describe("query construction", () => {
  it("covers every ecosystem the parsers emit, not just PyPI", () => {
    expect(ecosystemSearchTerms("npm")).toContain("npm");
    expect(ecosystemSearchTerms("PyPI")).toContain("Python");
    expect(ecosystemSearchTerms("Maven")).toContain("Java");
    expect(ecosystemSearchTerms("crates.io")).toContain("Rust");
    expect(ecosystemSearchTerms("NuGet")).toContain(".NET");
    expect(ecosystemSearchTerms("RubyGems")).toContain("Ruby");
    expect(ecosystemSearchTerms("Packagist")).toContain("PHP");
    expect(ecosystemSearchTerms("Go")).toContain("Go");
    expect(ecosystemSearchTerms("Hex")).toContain("Elixir");
    expect(ecosystemSearchTerms("Pub")).toContain("Dart");
    expect(ecosystemSearchTerms("SwiftPM")).toContain("Swift");
  });

  it("falls back to the raw label for an unknown registry", () => {
    expect(ecosystemSearchTerms("conan")).toBe("conan");
  });

  it("quotes the package name so the search is about the package", () => {
    expect(buildPackageQuery("crossenv", "npm")).toContain('"crossenv"');
  });

  // Measured: without threat terms, real attacks return nothing because
  // malicious packages are removed from the registry.
  it("includes threat terms so removed packages are still findable", () => {
    const q = buildPackageQuery("colourama", "PyPI");
    expect(q).toMatch(/malicious|malware|advisory/);
  });
});

describe("mentionsPackage", () => {
  it("keeps results that name the package", () => {
    expect(
      mentionsPackage(hit({ title: "`crossenv` malware on npm" }), "crossenv"),
    ).toBe(true);
  });

  it("drops results that never name it", () => {
    expect(
      mentionsPackage(hit({ title: "Hunting typosquatters on npm" }), "crossenv"),
    ).toBe(false);
  });

  it("matches on the excerpt and URL too", () => {
    expect(mentionsPackage(hit({ excerpt: "the colourama package" }), "colourama")).toBe(true);
    expect(mentionsPackage(hit({ url: "https://x.test/pkg/colourama" }), "colourama")).toBe(true);
  });

  it("returns false for an empty name", () => {
    expect(mentionsPackage(hit(), "")).toBe(false);
  });
});

describe("researchPackage", () => {
  it("returns null when no API key is configured", async () => {
    delete process.env.TAVILY_API_KEY;
    const search = vi.fn();
    __setSearchProvider({ name: "stub", search });

    expect(await researchPackage("lodash", "npm")).toBeNull();
    expect(search).not.toHaveBeenCalled();
  });

  it("filters out results that do not name the package", async () => {
    // Searching for `lodash` really does return an advisory for the different
    // package `@lodash-en/lodash-en`; unrelated topic articles must not survive.
    __setSearchProvider({
      name: "stub",
      search: async () => [
        hit({ title: "`crossenv` malware on the npm registry" }),
        hit({ title: "Hunting typosquatters on npm" }),
      ],
    });

    const result = await researchPackage("crossenv", "npm");
    expect(result!.hits).toHaveLength(1);
    expect(result!.hits[0].title).toContain("crossenv");
  });

  it("returns an empty hit list rather than null when nothing names it", async () => {
    __setSearchProvider({ name: "stub", search: async () => [hit({ title: "unrelated" })] });

    const result = await researchPackage("crossenv", "npm");
    expect(result).not.toBeNull();
    expect(result!.hits).toEqual([]);
  });

  it("caches by ecosystem and name", async () => {
    const search = vi.fn(async () => [hit({ title: "lodash docs" })]);
    __setSearchProvider({ name: "stub", search });

    await researchPackage("lodash", "npm");
    await researchPackage("lodash", "npm");
    expect(search).toHaveBeenCalledTimes(1);

    // A different registry is a different package.
    await researchPackage("lodash", "PyPI");
    expect(search).toHaveBeenCalledTimes(2);
  });

  it("returns null on provider failure and does not cache it", async () => {
    const search = vi
      .fn()
      .mockRejectedValueOnce(new Error("network"))
      .mockResolvedValueOnce([hit({ title: "lodash docs" })]);
    __setSearchProvider({ name: "stub", search });

    expect(await researchPackage("lodash", "npm")).toBeNull();
    // A transient failure must not suppress later attempts.
    expect((await researchPackage("lodash", "npm"))!.hits).toHaveLength(1);
  });

  it("records the provider for the audit trail", async () => {
    __setSearchProvider({ name: "stub", search: async () => [] });
    expect((await researchPackage("lodash", "npm"))!.provider).toBe("stub");
  });
});

describe("formatResearchEvidence", () => {
  it("states that no reports means unknown, not safe", () => {
    const text = formatResearchEvidence({ query: "q", hits: [], provider: "stub" });
    expect(text).toMatch(/UNKNOWN, not safe/i);
  });

  it("includes the URL so a verdict can be checked", () => {
    const text = formatResearchEvidence({
      query: "q",
      hits: [hit({ title: "Malicious Package in colourama | Snyk", url: "https://snyk.test/x" })],
      provider: "stub",
    });
    expect(text).toContain("https://snyk.test/x");
    expect(text).toContain("colourama");
  });
});
