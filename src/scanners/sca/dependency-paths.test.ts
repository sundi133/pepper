import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  attachDependencyPaths,
  findPathInGraph,
  formatDependencyPath,
  resolveDependencyPaths,
} from "./dependency-paths";
import { __clearDepsDevGraphCache, type DepsDevGraph } from "./deps-dev-client";
import type { Dependency } from "../types";

function dep(name: string, version = "1.0.0", ecosystem = "npm"): Dependency {
  return { name, version, ecosystem };
}

function presence(deps: Dependency[]) {
  const map = new Map<string, Set<string>>();
  for (const d of deps) {
    const set = map.get(d.name) ?? new Set<string>();
    set.add(d.version);
    map.set(d.name, set);
  }
  return map;
}

/** express@4.18.2 → body-parser@1.20.1 → qs@6.11.0, plus a decoy branch. */
function graph(): DepsDevGraph {
  return {
    nodes: [
      { name: "express", version: "4.18.2", relation: "SELF", bundled: false },
      { name: "body-parser", version: "1.20.1", relation: "DIRECT", bundled: false },
      { name: "qs", version: "6.11.0", relation: "INDIRECT", bundled: false },
      { name: "accepts", version: "1.3.8", relation: "DIRECT", bundled: false },
    ],
    edges: [
      { from: 0, to: 1 },
      { from: 0, to: 3 },
      { from: 1, to: 2 },
    ],
  };
}

const realFetch = global.fetch;

function mockGraphFetch(g: DepsDevGraph) {
  // Shape matches the live deps.dev :dependencies response.
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => ({
      nodes: g.nodes.map((n) => ({
        versionKey: { system: "NPM", name: n.name, version: n.version },
        relation: n.relation,
        bundled: n.bundled,
      })),
      edges: g.edges.map((e) => ({
        fromNode: e.from,
        toNode: e.to,
        requirement: e.requirement,
      })),
      error: "",
    }),
  });
}

beforeEach(() => {
  __clearDepsDevGraphCache();
});

afterEach(() => {
  global.fetch = realFetch;
  vi.restoreAllMocks();
});

describe("findPathInGraph", () => {
  const all = [
    dep("express", "4.18.2"),
    dep("body-parser", "1.20.1"),
    dep("qs", "6.11.0"),
    dep("accepts", "1.3.8"),
  ];

  it("finds the chain to a transitive package", () => {
    const hit = findPathInGraph(graph(), "qs", presence(all));
    expect(hit?.path).toEqual([
      "express@4.18.2",
      "body-parser@1.20.1",
      "qs@6.11.0",
    ]);
    expect(hit?.exactVersionMatch).toBe(true);
  });

  it("returns null for a package absent from the graph", () => {
    expect(findPathInGraph(graph(), "not-here", presence(all))).toBeNull();
  });

  it("reports an inexact version match when the project resolved differently", () => {
    // Upstream resolution says qs@6.11.0; this project pinned 6.9.0.
    const pinned = [
      dep("express", "4.18.2"),
      dep("body-parser", "1.20.1"),
      dep("qs", "6.9.0"),
    ];
    const hit = findPathInGraph(graph(), "qs", presence(pinned));
    expect(hit).not.toBeNull();
    expect(hit?.exactVersionMatch).toBe(false);
  });

  it("does not route through a package the project does not have", () => {
    // body-parser is missing locally, so the only route to qs is uncorroborated.
    const withoutBodyParser = [dep("express", "4.18.2"), dep("qs", "6.11.0")];
    expect(findPathInGraph(graph(), "qs", presence(withoutBodyParser))).toBeNull();
  });

  it("picks the shortest path when several exist", () => {
    const g: DepsDevGraph = {
      nodes: [
        { name: "root", version: "1.0.0", relation: "SELF", bundled: false },
        { name: "mid", version: "1.0.0", relation: "DIRECT", bundled: false },
        { name: "target", version: "1.0.0", relation: "DIRECT", bundled: false },
      ],
      edges: [
        { from: 0, to: 1 },
        { from: 1, to: 2 },
        { from: 0, to: 2 },
      ],
    };
    const hit = findPathInGraph(
      g,
      "target",
      presence([dep("root"), dep("mid"), dep("target")]),
    );
    expect(hit?.path).toEqual(["root@1.0.0", "target@1.0.0"]);
  });

  it("terminates on a cyclic graph", () => {
    const cyclic: DepsDevGraph = {
      nodes: [
        { name: "a", version: "1.0.0", relation: "SELF", bundled: false },
        { name: "b", version: "1.0.0", relation: "DIRECT", bundled: false },
      ],
      edges: [
        { from: 0, to: 1 },
        { from: 1, to: 0 },
      ],
    };
    expect(
      findPathInGraph(cyclic, "missing", presence([dep("a"), dep("b")])),
    ).toBeNull();
  });

  it("handles an empty graph", () => {
    expect(findPathInGraph({ nodes: [], edges: [] }, "x", new Map())).toBeNull();
  });
});

describe("resolveDependencyPaths", () => {
  const all = [
    dep("express", "4.18.2"),
    dep("body-parser", "1.20.1"),
    dep("qs", "6.11.0"),
    dep("accepts", "1.3.8"),
  ];
  const direct = new Set(["express"]);

  it("explains a transitive package via its direct dependency", async () => {
    global.fetch = mockGraphFetch(graph()) as never;

    const paths = await resolveDependencyPaths(new Set(["qs"]), all, direct);

    expect(paths.get("qs")).toMatchObject({
      introducedBy: "express",
      exactVersionMatch: true,
    });
    expect(paths.get("qs")?.path).toEqual([
      "express@4.18.2",
      "body-parser@1.20.1",
      "qs@6.11.0",
    ]);
  });

  it("resolves a direct dependency without any network call", async () => {
    const fetchMock = mockGraphFetch(graph());
    global.fetch = fetchMock as never;

    const paths = await resolveDependencyPaths(new Set(["express"]), all, direct);

    expect(paths.get("express")).toEqual({
      path: ["express@4.18.2"],
      introducedBy: "express",
      exactVersionMatch: true,
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns an empty map for no targets", async () => {
    const fetchMock = mockGraphFetch(graph());
    global.fetch = fetchMock as never;

    expect((await resolveDependencyPaths(new Set(), all, direct)).size).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("omits packages it cannot explain rather than guessing", async () => {
    global.fetch = mockGraphFetch(graph()) as never;

    const paths = await resolveDependencyPaths(
      new Set(["mystery-pkg"]),
      all,
      direct,
    );

    expect(paths.has("mystery-pkg")).toBe(false);
  });

  it("degrades quietly when the graph request fails", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("network down")) as never;

    const paths = await resolveDependencyPaths(new Set(["qs"]), all, direct);
    expect(paths.size).toBe(0);
  });

  it("reports truncation instead of silently capping coverage", async () => {
    global.fetch = mockGraphFetch(graph()) as never;
    const onProgress = vi.fn();
    const manyDirect = Array.from({ length: 5 }, (_, i) => dep(`d${i}`));

    await resolveDependencyPaths(
      new Set(["qs"]),
      [...manyDirect, ...all],
      new Set(manyDirect.map((d) => d.name)),
      { maxGraphFetches: 2, onProgress },
    );

    expect(onProgress).toHaveBeenCalledWith(
      expect.stringContaining("limited to 2 of 5"),
    );
  });

  it("stops when the scan is aborted", async () => {
    const fetchMock = mockGraphFetch(graph());
    global.fetch = fetchMock as never;
    const controller = new AbortController();
    controller.abort();

    const paths = await resolveDependencyPaths(new Set(["qs"]), all, direct, {
      signal: controller.signal,
    });

    expect(paths.size).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("attachDependencyPaths", () => {
  const path = {
    path: ["express@4.18.2", "qs@6.11.0"],
    introducedBy: "express",
    exactVersionMatch: true,
  };

  type Finding = { metadata?: Record<string, unknown> };

  it("adds path metadata to the matching finding", () => {
    const findings: Finding[] = [{ metadata: { packageName: "qs" } }];
    const result = attachDependencyPaths(findings, new Map([["qs", path]]));

    expect(result[0].metadata).toMatchObject({
      introducedBy: "express",
      dependencyPathText: "express@4.18.2 → qs@6.11.0",
      dependencyPathExactVersions: true,
    });
  });

  it("leaves unexplained findings untouched", () => {
    const findings: Finding[] = [{ metadata: { packageName: "other" } }];
    const result = attachDependencyPaths(findings, new Map([["qs", path]]));
    expect(result[0].metadata?.introducedBy).toBeUndefined();
  });

  it("returns findings unchanged when there are no paths", () => {
    const findings: Finding[] = [{ metadata: { packageName: "qs" } }];
    expect(attachDependencyPaths(findings, new Map())).toBe(findings);
  });

  it("tolerates findings with no package name", () => {
    const findings: Finding[] = [{ metadata: {} }];
    expect(() => attachDependencyPaths(findings, new Map([["qs", path]]))).not.toThrow();
  });
});

describe("formatDependencyPath", () => {
  it("renders the chain with arrows", () => {
    expect(
      formatDependencyPath({
        path: ["a@1", "b@2", "c@3"],
        introducedBy: "a",
        exactVersionMatch: true,
      }),
    ).toBe("a@1 → b@2 → c@3");
  });
});
