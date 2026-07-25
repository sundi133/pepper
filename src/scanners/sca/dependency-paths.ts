/**
 * Explains *why* a vulnerable transitive dependency is present, and which
 * direct dependency introduced it.
 *
 * Lockfiles hold the project's real resolved tree but express it differently in
 * every format; deps.dev exposes a resolved graph per published package version
 * but that is the *upstream* resolution, which can differ from what a given
 * project actually installed.
 *
 * So paths are taken from deps.dev and then **corroborated** against the
 * project's own parsed dependency set: a hop is only accepted when that package
 * genuinely appears in the project. Versions are reported as exactly matching
 * only when they really do, because upstream resolution routinely picks a
 * different patch release than a pinned lockfile. A path that cannot be
 * corroborated is not reported at all — an unexplained finding is better than a
 * fabricated explanation.
 */

import type { Dependency } from "../types";
import {
  fetchDependencyGraph,
  dependencyKey,
  type DepsDevGraph,
} from "./deps-dev-client";
import { DEPS_DEV_MAX_GRAPH_FETCHES } from "@/lib/constants";
import { logger } from "@/lib/logger";

export interface DependencyPath {
  /** Hops from the direct dependency to the target, e.g. ["express@4.18.2", "qs@6.11.0"]. */
  path: string[];
  /** The direct dependency that pulls the target in. */
  introducedBy: string;
  /** True when every hop's version matched the project's resolved version. */
  exactVersionMatch: boolean;
}

/** Index of the packages a project actually has, by name → versions. */
function buildPresenceIndex(
  dependencies: Dependency[],
): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();
  for (const dep of dependencies) {
    const versions = index.get(dep.name) ?? new Set<string>();
    versions.add(dep.version);
    index.set(dep.name, versions);
  }
  return index;
}

/**
 * Shortest corroborated path from a graph's SELF node to `targetName`.
 * Breadth-first, so the first path found is the shortest.
 */
export function findPathInGraph(
  graph: DepsDevGraph,
  targetName: string,
  present: Map<string, Set<string>>,
): { path: string[]; exactVersionMatch: boolean } | null {
  if (graph.nodes.length === 0) return null;

  const selfIndex = graph.nodes.findIndex((n) => n.relation === "SELF");
  const root = selfIndex >= 0 ? selfIndex : 0;

  // Adjacency list keyed by node index.
  const adjacency = new Map<number, number[]>();
  for (const edge of graph.edges) {
    const list = adjacency.get(edge.from) ?? [];
    list.push(edge.to);
    adjacency.set(edge.from, list);
  }

  const visited = new Set<number>([root]);
  let frontier: number[][] = [[root]];

  while (frontier.length > 0) {
    const next: number[][] = [];

    for (const trail of frontier) {
      const current = trail[trail.length - 1];

      for (const neighbour of adjacency.get(current) ?? []) {
        if (visited.has(neighbour)) continue;

        const node = graph.nodes[neighbour];
        if (!node?.name) continue;

        // Only traverse through packages the project actually has, so a path
        // never runs through a package that is not in this project's tree.
        if (!present.has(node.name)) {
          visited.add(neighbour);
          continue;
        }

        const trailToNode = [...trail, neighbour];

        if (node.name === targetName) {
          const nodes = trailToNode.map((i) => graph.nodes[i]);
          return {
            path: nodes.map((n) => `${n.name}@${n.version}`),
            exactVersionMatch: nodes.every((n) =>
              present.get(n.name)?.has(n.version) ?? false,
            ),
          };
        }

        visited.add(neighbour);
        next.push(trailToNode);
      }
    }

    frontier = next;
  }

  return null;
}

/**
 * Resolve dependency paths for the given target packages.
 *
 * Only fetches graphs for direct dependencies, and only while there are targets
 * left to explain. Returns a map keyed by target package *name*, since a
 * vulnerability is reported per package.
 */
export async function resolveDependencyPaths(
  targetNames: Set<string>,
  allDependencies: Dependency[],
  directDependencies: Set<string>,
  options: {
    signal?: AbortSignal;
    maxGraphFetches?: number;
    onProgress?: (message: string) => void;
  } = {},
): Promise<Map<string, DependencyPath>> {
  const results = new Map<string, DependencyPath>();
  if (targetNames.size === 0) return results;

  const present = buildPresenceIndex(allDependencies);
  const remaining = new Set(targetNames);

  // A target that is itself a direct dependency needs no graph lookup.
  for (const dep of allDependencies) {
    if (!remaining.has(dep.name) || !directDependencies.has(dep.name)) continue;
    results.set(dep.name, {
      path: [`${dep.name}@${dep.version}`],
      introducedBy: dep.name,
      exactVersionMatch: true,
    });
    remaining.delete(dep.name);
  }

  if (remaining.size === 0) return results;

  const directDeps = allDependencies.filter((d) =>
    directDependencies.has(d.name),
  );
  const maxFetches = options.maxGraphFetches ?? DEPS_DEV_MAX_GRAPH_FETCHES;
  const budgeted = directDeps.slice(0, maxFetches);

  if (directDeps.length > budgeted.length) {
    // Never let a bounded search look like exhaustive coverage.
    const message =
      `SCA: dependency-path search limited to ${budgeted.length} of ` +
      `${directDeps.length} direct dependencies`;
    logger.info(
      { limit: budgeted.length, directDependencies: directDeps.length },
      "dependency-path search truncated",
    );
    options.onProgress?.(message);
  }

  for (const direct of budgeted) {
    if (options.signal?.aborted || remaining.size === 0) break;

    const graph = await fetchDependencyGraph(direct);
    if (!graph) continue;

    // Only names in this graph can be explained by it.
    const graphNames = new Set(graph.nodes.map((n) => n.name));

    for (const targetName of [...remaining]) {
      if (!graphNames.has(targetName)) continue;

      const hit = findPathInGraph(graph, targetName, present);
      if (!hit) continue;

      results.set(targetName, {
        path: hit.path,
        introducedBy: direct.name,
        exactVersionMatch: hit.exactVersionMatch,
      });
      remaining.delete(targetName);
    }
  }

  return results;
}

/** Human-readable path, e.g. "express@4.18.2 → body-parser@1.20.1 → qs@6.11.0". */
export function formatDependencyPath(path: DependencyPath): string {
  return path.path.join(" → ");
}

/**
 * Attach path explanations to SCA findings.
 * Findings whose package could not be explained are returned unchanged.
 */
export function attachDependencyPaths<
  T extends { metadata?: Record<string, unknown> },
>(findings: T[], paths: Map<string, DependencyPath>): T[] {
  if (paths.size === 0) return findings;

  return findings.map((finding) => {
    const packageName = finding.metadata?.packageName as string | undefined;
    if (!packageName) return finding;

    const resolved = paths.get(packageName);
    if (!resolved) return finding;

    return {
      ...finding,
      metadata: {
        ...finding.metadata,
        dependencyPath: resolved.path,
        dependencyPathText: formatDependencyPath(resolved),
        introducedBy: resolved.introducedBy,
        dependencyPathExactVersions: resolved.exactVersionMatch,
      },
    };
  });
}

export { dependencyKey };
