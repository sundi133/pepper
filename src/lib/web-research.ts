/**
 * Web corroboration for supply-chain findings.
 *
 * Answers the one question no registry API can: has anyone publicly *reported*
 * this package as malicious? Advisory feeds cover what has been catalogued;
 * incident write-ups and vendor blogs often precede them by days.
 *
 * Two properties are deliberate, and both come from measuring the naive design
 * before building this one.
 *
 * 1. FLAG ONLY, NEVER CLEAR. Search results are attacker-influenceable — anyone
 *    can publish a page asserting a package is safe and widely used. A result
 *    may raise suspicion; only registry facts (ownership, release history) may
 *    dismiss a finding. Trust is asymmetric on purpose.
 *
 * 2. THE PACKAGE MUST BE NAMED. Querying "<package> malicious typosquat"
 *    retrieves articles about typosquatting in general, which inverts the
 *    signal: searching that way returned nothing about `colourama`, a real PyPI
 *    attack, while returning three malware articles for `mcp`, which is
 *    Anthropic's official SDK. Queries use the exact quoted name and results
 *    that never mention it are discarded before anything sees them.
 *
 * Even filtered, a hit is not a verdict — `colourama` also matches a printing
 * company. Results are evidence for a model to judge, never a finding on their
 * own.
 */

import { logger } from "@/lib/logger";
import {
  ENABLE_WEB_RESEARCH,
  WEB_RESEARCH_CACHE_TTL_MS,
  WEB_RESEARCH_MAX_RESULTS,
  WEB_RESEARCH_TIMEOUT_MS,
} from "@/lib/constants";

export interface WebResearchHit {
  title: string;
  url: string;
  /** Extract from the page, truncated for prompt budget. */
  excerpt: string;
  /** Provider relevance score, when supplied. */
  score?: number;
}

export interface WebResearchResult {
  query: string;
  hits: WebResearchHit[];
  /** Provider that answered, for audit trails. */
  provider: string;
}

const MAX_EXCERPT_CHARS = 400;

// ─── Provider ────────────────────────────────────────────────────────────────

interface SearchProvider {
  name: string;
  search(query: string, signal?: AbortSignal): Promise<WebResearchHit[]>;
}

interface TavilyResponse {
  results?: Array<{
    title?: string;
    url?: string;
    content?: string;
    score?: number;
  }>;
}

const tavilyProvider: SearchProvider = {
  name: "tavily",
  async search(query, signal) {
    const apiKey = process.env.TAVILY_API_KEY;
    if (!apiKey) return [];

    const response = await fetch("https://api.tavily.com/search", {
      method: "POST",
      headers: {
        // The key is only ever read from the environment and never logged.
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query,
        max_results: WEB_RESEARCH_MAX_RESULTS,
        search_depth: "advanced",
      }),
      signal: signal ?? AbortSignal.timeout(WEB_RESEARCH_TIMEOUT_MS),
    });

    if (!response.ok) {
      // Status only — never the key or the response body, which may echo it.
      logger.warn({ status: response.status }, "web research request failed");
      return [];
    }

    const data = (await response.json()) as TavilyResponse;
    return (data.results || [])
      .filter((r) => r.url && r.title)
      .map((r) => ({
        title: (r.title || "").trim(),
        url: (r.url || "").trim(),
        excerpt: (r.content || "").trim().slice(0, MAX_EXCERPT_CHARS),
        score: typeof r.score === "number" ? r.score : undefined,
      }));
  },
};

/** Swappable for tests and for adding providers later. */
let activeProvider: SearchProvider = tavilyProvider;

export function __setSearchProvider(provider: SearchProvider): void {
  activeProvider = provider;
}

export function __resetSearchProvider(): void {
  activeProvider = tavilyProvider;
}

// ─── Cache ───────────────────────────────────────────────────────────────────
// Keyed by ecosystem and name only: whether a package has been reported is
// independent of which organisation is scanning, so one lookup serves everyone.

const _cache = new Map<
  string,
  { result: WebResearchResult | null; fetchedAt: number }
>();

export function __clearWebResearchCache(): void {
  _cache.clear();
}

// ─── Public API ──────────────────────────────────────────────────────────────

/** True when a result actually concerns the package, not the topic. */
export function mentionsPackage(hit: WebResearchHit, name: string): boolean {
  const needle = name.toLowerCase().trim();
  if (!needle) return false;
  return `${hit.title} ${hit.excerpt} ${hit.url}`.toLowerCase().includes(needle);
}

/**
 * Search terms per registry, so a query reads the way people write about that
 * language. The raw ecosystem labels the parsers emit ("crates.io", "SwiftPM")
 * are not always how a package is discussed in advisories and blog posts.
 */
const ECOSYSTEM_SEARCH_TERMS: Record<string, string> = {
  npm: "npm JavaScript",
  pypi: "PyPI Python",
  pip: "PyPI Python",
  maven: "Maven Java",
  gradle: "Maven Java",
  go: "Go module",
  golang: "Go module",
  "crates.io": "crates.io Rust",
  cargo: "crates.io Rust",
  nuget: "NuGet .NET",
  rubygems: "RubyGems Ruby",
  gem: "RubyGems Ruby",
  packagist: "Composer PHP",
  composer: "Composer PHP",
  pub: "pub.dev Dart",
  hex: "Hex Elixir",
  swiftpm: "Swift Package Manager",
  swift: "Swift Package Manager",
};

/** Registry search terms, falling back to the raw label for unknown registries. */
export function ecosystemSearchTerms(ecosystem: string): string {
  return ECOSYSTEM_SEARCH_TERMS[(ecosystem || "").toLowerCase().trim()] || ecosystem;
}

/**
 * Query for public reports about a package.
 *
 * Both halves are load-bearing, and both were measured. Without the threat
 * terms the search returns documentation pages, which finds nothing for a
 * malicious package because those get removed from the registry: `crossenv` and
 * `colourama`, both real attacks, returned zero results that way while every
 * legitimate package returned five. With the threat terms but no quoted name it
 * returns general articles about typosquatting, which match innocent packages.
 * Quoted name plus threat terms retrieves the actual advisories — the npm
 * `crossenv` post, Snyk's `colourama` write-up — for real attacks.
 *
 * Precision is NOT solved here. "@lodash-en/lodash-en (npm) malicious package"
 * is returned when searching for `lodash`, because the malicious package's name
 * contains it. Deciding whether a report concerns THIS package is a judgement
 * left to the model that reads the evidence.
 */
export function buildPackageQuery(name: string, ecosystem: string): string {
  return `"${name}" ${ecosystemSearchTerms(ecosystem)} package malicious malware removed advisory`;
}

/**
 * Look for public reports about a package.
 *
 * Returns `null` when research is disabled, unconfigured or failed — meaning
 * "unknown". Callers must never read `null` or an empty result as evidence that
 * a package is safe.
 */
export async function researchPackage(
  name: string,
  ecosystem: string,
  options: { signal?: AbortSignal } = {},
): Promise<WebResearchResult | null> {
  if (!ENABLE_WEB_RESEARCH || !process.env.TAVILY_API_KEY) return null;
  if (!name?.trim()) return null;

  const key = `${ecosystem.toLowerCase()}:${name.toLowerCase()}`;
  const cached = _cache.get(key);
  if (cached && Date.now() - cached.fetchedAt <= WEB_RESEARCH_CACHE_TTL_MS) {
    return cached.result;
  }

  const query = buildPackageQuery(name, ecosystem);

  try {
    const hits = await activeProvider.search(query, options.signal);
    // Discard anything that does not name the package: without this the results
    // describe the topic rather than the package, which inverts the signal.
    const named = hits.filter((h) => mentionsPackage(h, name));

    const result: WebResearchResult = {
      query,
      hits: named,
      provider: activeProvider.name,
    };
    _cache.set(key, { result, fetchedAt: Date.now() });
    return result;
  } catch (err) {
    logger.warn(
      { err: err instanceof Error ? err.message : "unknown", name },
      "web research errored",
    );
    // Not cached: a transient failure should not suppress later attempts.
    return null;
  }
}

/** Compact, quotable evidence block for a prompt. */
export function formatResearchEvidence(result: WebResearchResult): string {
  if (result.hits.length === 0) {
    return "No public reports found that name this package. This means UNKNOWN, not safe.";
  }
  return result.hits
    .map((h) => `- ${h.title}\n  ${h.url}\n  ${h.excerpt}`)
    .join("\n");
}
