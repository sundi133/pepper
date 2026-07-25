/**
 * deps.dev (Google Open Source Insights) client.
 *
 * Supplies the declared license, source repository, deprecation status and
 * provenance/attestation presence for a dependency version — data that no
 * lockfile carries and that OSV does not return.
 *
 * Purely additive: every failure path degrades to `null` so a scan never fails
 * because deps.dev was slow, rate-limited or unreachable. Callers must treat a
 * `null` result as "unknown", never as "clean".
 */

import type { Dependency } from "../types";
import { logger } from "@/lib/logger";
import {
  DEPS_DEV_API_URL,
  DEPS_DEV_CACHE_TTL_MS,
  DEPS_DEV_CONCURRENCY,
  DEPS_DEV_MAX_CACHE_ENTRIES,
  DEPS_DEV_TIMEOUT_MS,
} from "@/lib/constants";

/**
 * Pepper ecosystem label → deps.dev system. Verified against the live API.
 * Packagist, Pub, Hex and SwiftPM have no deps.dev coverage and are skipped.
 */
const SYSTEM_BY_ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  pypi: "pypi",
  pip: "pypi",
  maven: "maven",
  gradle: "maven",
  go: "go",
  golang: "go",
  "crates.io": "cargo",
  cargo: "cargo",
  crates: "cargo",
  nuget: "nuget",
  rubygems: "rubygems",
  gem: "rubygems",
};

/** deps.dev marker for a license string it could not map to SPDX. */
export const NON_STANDARD_LICENSE = "non-standard";

export interface DepsDevVersionInfo {
  /** SPDX license expressions as declared upstream, e.g. ["Apache-2.0 OR MIT"]. */
  licenses: string[];
  sourceRepo?: string;
  publishedAt?: string;
  isDeprecated: boolean;
  deprecatedReason?: string;
  /** SLSA provenance published for this version (supply-chain integrity signal). */
  hasSlsaProvenance: boolean;
  hasAttestations: boolean;
}

interface DepsDevVersionResponse {
  versionKey?: { system?: string; name?: string; version?: string };
  publishedAt?: string;
  isDeprecated?: boolean;
  deprecatedReason?: string;
  licenses?: string[];
  links?: Array<{ label?: string; url?: string }>;
  slsaProvenances?: unknown[];
  attestations?: unknown[];
}

export function depsDevSystemFor(ecosystem: string): string | undefined {
  return SYSTEM_BY_ECOSYSTEM[ecosystem.toLowerCase()];
}

/** True when deps.dev can resolve this dependency's ecosystem. */
export function isSupportedByDepsDev(dep: Dependency): boolean {
  return depsDevSystemFor(dep.ecosystem) !== undefined;
}

function cacheKey(system: string, name: string, version: string): string {
  return `${system}:${name}@${version}`;
}

// ─── Cache ───────────────────────────────────────────────────────────────────
// Package metadata is org-independent and effectively immutable per version, so
// it is cached process-wide and shared across scans. `null` is cached too — a
// 404 for a version will keep 404-ing and should not be retried per scan.

const _cache = new Map<
  string,
  { info: DepsDevVersionInfo | null; fetchedAt: number }
>();

function cacheGet(key: string): { info: DepsDevVersionInfo | null } | undefined {
  const hit = _cache.get(key);
  if (!hit) return undefined;
  if (Date.now() - hit.fetchedAt > DEPS_DEV_CACHE_TTL_MS) {
    _cache.delete(key);
    return undefined;
  }
  return hit;
}

function cacheSet(key: string, info: DepsDevVersionInfo | null): void {
  // Simple FIFO bound — evict the oldest insertion when over capacity.
  if (_cache.size >= DEPS_DEV_MAX_CACHE_ENTRIES) {
    const oldest = _cache.keys().next();
    if (!oldest.done) _cache.delete(oldest.value);
  }
  _cache.set(key, { info, fetchedAt: Date.now() });
}

/** Test seam — clears the process-wide metadata cache. */
export function __clearDepsDevCache(): void {
  _cache.clear();
}

// ─── Fetch ───────────────────────────────────────────────────────────────────

function parseResponse(data: DepsDevVersionResponse): DepsDevVersionInfo {
  const sourceRepo = data.links?.find((l) => l.label === "SOURCE_REPO")?.url;
  return {
    licenses: (data.licenses || []).filter(
      (l): l is string => typeof l === "string" && l.length > 0,
    ),
    sourceRepo,
    publishedAt: data.publishedAt,
    isDeprecated: data.isDeprecated === true,
    deprecatedReason: data.deprecatedReason || undefined,
    hasSlsaProvenance: (data.slsaProvenances?.length ?? 0) > 0,
    hasAttestations: (data.attestations?.length ?? 0) > 0,
  };
}

/**
 * Fetch metadata for one dependency version.
 * Returns `null` for unsupported ecosystems, unknown versions, and any failure.
 */
export async function fetchVersionInfo(
  dep: Dependency,
  apiUrl = DEPS_DEV_API_URL,
): Promise<DepsDevVersionInfo | null> {
  const system = depsDevSystemFor(dep.ecosystem);
  if (!system || !dep.name || !dep.version) return null;

  const key = cacheKey(system, dep.name, dep.version);
  const cached = cacheGet(key);
  if (cached) return cached.info;

  // Names carry characters that must survive path encoding: Maven uses
  // "group:artifact" and Go uses full module paths with slashes.
  const url =
    `${apiUrl}/v3/systems/${system}/packages/${encodeURIComponent(dep.name)}` +
    `/versions/${encodeURIComponent(dep.version)}`;

  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(DEPS_DEV_TIMEOUT_MS),
      headers: { Accept: "application/json" },
    });

    if (response.status === 404) {
      // Unknown package/version — cache so we do not ask again.
      cacheSet(key, null);
      return null;
    }

    if (!response.ok) {
      // Transient (429/5xx): do not cache, so a later scan can retry.
      logger.warn(
        { status: response.status, system, name: dep.name },
        "deps.dev version request failed",
      );
      return null;
    }

    const info = parseResponse((await response.json()) as DepsDevVersionResponse);
    cacheSet(key, info);
    return info;
  } catch (err) {
    logger.warn(
      { err, system, name: dep.name },
      "deps.dev version request errored",
    );
    return null;
  }
}

/**
 * Fetch metadata for many dependencies with bounded concurrency.
 * Keyed by `ecosystem:name@version` so callers can look results up directly.
 */
export async function fetchVersionInfoBatch(
  dependencies: Dependency[],
  options: {
    apiUrl?: string;
    concurrency?: number;
    signal?: AbortSignal;
    onProgress?: (done: number, total: number) => void;
  } = {},
): Promise<Map<string, DepsDevVersionInfo>> {
  const apiUrl = options.apiUrl ?? DEPS_DEV_API_URL;
  const concurrency = options.concurrency ?? DEPS_DEV_CONCURRENCY;
  const result = new Map<string, DepsDevVersionInfo>();

  const supported = dependencies.filter(isSupportedByDepsDev);
  if (supported.length === 0) return result;

  for (let i = 0; i < supported.length; i += concurrency) {
    if (options.signal?.aborted) break;

    const batch = supported.slice(i, i + concurrency);
    const settled = await Promise.allSettled(
      batch.map((dep) => fetchVersionInfo(dep, apiUrl)),
    );

    for (let j = 0; j < settled.length; j++) {
      const outcome = settled[j];
      if (outcome.status !== "fulfilled" || !outcome.value) continue;
      const dep = batch[j];
      result.set(dependencyKey(dep), outcome.value);
    }

    options.onProgress?.(Math.min(i + concurrency, supported.length), supported.length);
  }

  return result;
}

/** Stable lookup key for a dependency, matching fetchVersionInfoBatch results. */
export function dependencyKey(dep: Dependency): string {
  return `${dep.ecosystem}:${dep.name}@${dep.version}`;
}

// ─── Dependency graph ────────────────────────────────────────────────────────
// deps.dev resolves the dependency graph for a *published* package version.
// That is the upstream resolution, which may differ from a project's own
// lockfile, so callers must corroborate paths against the project's real
// dependency set before presenting them. See ./dependency-paths.ts.

export interface DepsDevGraphNode {
  name: string;
  version: string;
  /** SELF is the queried package; DIRECT and INDIRECT are its dependencies. */
  relation: "SELF" | "DIRECT" | "INDIRECT";
  bundled: boolean;
}

export interface DepsDevGraph {
  nodes: DepsDevGraphNode[];
  /** Edges reference nodes by index. */
  edges: Array<{ from: number; to: number; requirement?: string }>;
}

interface DepsDevGraphResponse {
  nodes?: Array<{
    versionKey?: { system?: string; name?: string; version?: string };
    relation?: string;
    bundled?: boolean;
  }>;
  edges?: Array<{ fromNode?: number; toNode?: number; requirement?: string }>;
  error?: string;
}

const _graphCache = new Map<
  string,
  { graph: DepsDevGraph | null; fetchedAt: number }
>();

/** Test seam — clears the process-wide graph cache. */
export function __clearDepsDevGraphCache(): void {
  _graphCache.clear();
}

function normaliseRelation(relation?: string): DepsDevGraphNode["relation"] {
  const value = (relation || "").toUpperCase();
  if (value === "SELF") return "SELF";
  if (value === "DIRECT") return "DIRECT";
  return "INDIRECT";
}

/**
 * Fetch the resolved dependency graph for one package version.
 * Returns `null` for unsupported ecosystems, unknown versions and any failure.
 */
export async function fetchDependencyGraph(
  dep: Dependency,
  apiUrl = DEPS_DEV_API_URL,
): Promise<DepsDevGraph | null> {
  const system = depsDevSystemFor(dep.ecosystem);
  if (!system || !dep.name || !dep.version) return null;

  const key = cacheKey(system, dep.name, dep.version);
  const cached = _graphCache.get(key);
  if (cached && Date.now() - cached.fetchedAt <= DEPS_DEV_CACHE_TTL_MS) {
    return cached.graph;
  }
  if (cached) _graphCache.delete(key);

  const url =
    `${apiUrl}/v3/systems/${system}/packages/${encodeURIComponent(dep.name)}` +
    `/versions/${encodeURIComponent(dep.version)}:dependencies`;

  const store = (graph: DepsDevGraph | null) => {
    if (_graphCache.size >= DEPS_DEV_MAX_CACHE_ENTRIES) {
      const oldest = _graphCache.keys().next();
      if (!oldest.done) _graphCache.delete(oldest.value);
    }
    _graphCache.set(key, { graph, fetchedAt: Date.now() });
  };

  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(DEPS_DEV_TIMEOUT_MS),
      headers: { Accept: "application/json" },
    });

    if (response.status === 404) {
      store(null);
      return null;
    }
    if (!response.ok) {
      logger.warn(
        { status: response.status, system, name: dep.name },
        "deps.dev dependency graph request failed",
      );
      return null;
    }

    const data = (await response.json()) as DepsDevGraphResponse;

    const nodes: DepsDevGraphNode[] = (data.nodes || []).map((n) => ({
      name: n.versionKey?.name || "",
      version: n.versionKey?.version || "",
      relation: normaliseRelation(n.relation),
      bundled: n.bundled === true,
    }));

    const edges = (data.edges || [])
      .filter(
        (e) =>
          typeof e.fromNode === "number" &&
          typeof e.toNode === "number" &&
          e.fromNode >= 0 &&
          e.toNode >= 0 &&
          e.fromNode < nodes.length &&
          e.toNode < nodes.length,
      )
      .map((e) => ({
        from: e.fromNode as number,
        to: e.toNode as number,
        requirement: e.requirement || undefined,
      }));

    const graph: DepsDevGraph = { nodes, edges };
    store(graph);
    return graph;
  } catch (err) {
    logger.warn(
      { err, system, name: dep.name },
      "deps.dev dependency graph request errored",
    );
    return null;
  }
}
