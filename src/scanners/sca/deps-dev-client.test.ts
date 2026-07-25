import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  depsDevSystemFor,
  isSupportedByDepsDev,
  dependencyKey,
  fetchVersionInfo,
  fetchVersionInfoBatch,
  __clearDepsDevCache,
} from "./deps-dev-client";
import type { Dependency } from "../types";

function dep(over: Partial<Dependency> = {}): Dependency {
  return { name: "lodash", version: "4.17.21", ecosystem: "npm", ...over };
}

/** Minimal deps.dev version payload. */
function payload(over: Record<string, unknown> = {}) {
  return {
    versionKey: { system: "NPM", name: "lodash", version: "4.17.21" },
    publishedAt: "2021-02-20T15:42:16Z",
    isDeprecated: false,
    deprecatedReason: "",
    licenses: ["MIT"],
    links: [
      { label: "HOMEPAGE", url: "https://lodash.com/" },
      { label: "SOURCE_REPO", url: "git+https://github.com/lodash/lodash.git" },
    ],
    slsaProvenances: [],
    attestations: [],
    ...over,
  };
}

function mockFetchOnce(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  });
}

const realFetch = global.fetch;

beforeEach(() => {
  __clearDepsDevCache();
});

afterEach(() => {
  global.fetch = realFetch;
  vi.restoreAllMocks();
});

describe("ecosystem mapping", () => {
  it("maps the ecosystem labels Pepper's parsers actually emit", () => {
    expect(depsDevSystemFor("npm")).toBe("npm");
    expect(depsDevSystemFor("PyPI")).toBe("pypi");
    expect(depsDevSystemFor("Maven")).toBe("maven");
    expect(depsDevSystemFor("Go")).toBe("go");
    expect(depsDevSystemFor("crates.io")).toBe("cargo");
    expect(depsDevSystemFor("NuGet")).toBe("nuget");
    expect(depsDevSystemFor("RubyGems")).toBe("rubygems");
  });

  it("reports ecosystems deps.dev does not cover", () => {
    // Verified against the live API — these return no data.
    expect(depsDevSystemFor("Packagist")).toBeUndefined();
    expect(depsDevSystemFor("Pub")).toBeUndefined();
    expect(depsDevSystemFor("Hex")).toBeUndefined();
    expect(depsDevSystemFor("SwiftPM")).toBeUndefined();
    expect(isSupportedByDepsDev(dep({ ecosystem: "Hex" }))).toBe(false);
  });
});

describe("fetchVersionInfo", () => {
  it("parses licenses, source repo and provenance flags", async () => {
    global.fetch = mockFetchOnce(payload()) as never;

    const info = await fetchVersionInfo(dep());

    expect(info).not.toBeNull();
    expect(info!.licenses).toEqual(["MIT"]);
    expect(info!.sourceRepo).toBe("git+https://github.com/lodash/lodash.git");
    expect(info!.hasSlsaProvenance).toBe(false);
    expect(info!.isDeprecated).toBe(false);
  });

  it("detects SLSA provenance and attestations", async () => {
    global.fetch = mockFetchOnce(
      payload({ slsaProvenances: [{ sourceRepository: "x" }], attestations: [{}] }),
    ) as never;

    const info = await fetchVersionInfo(dep());
    expect(info!.hasSlsaProvenance).toBe(true);
    expect(info!.hasAttestations).toBe(true);
  });

  it("skips unsupported ecosystems without making a request", async () => {
    const fetchMock = mockFetchOnce(payload());
    global.fetch = fetchMock as never;

    expect(await fetchVersionInfo(dep({ ecosystem: "Hex" }))).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("URL-encodes Maven group:artifact names", async () => {
    const fetchMock = mockFetchOnce(payload({ licenses: ["Apache-2.0"] }));
    global.fetch = fetchMock as never;

    await fetchVersionInfo(
      dep({
        ecosystem: "Maven",
        name: "com.fasterxml.jackson.core:jackson-databind",
        version: "2.15.2",
      }),
    );

    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("%3Ajackson-databind");
    expect(url).toContain("/systems/maven/");
  });

  it("URL-encodes Go module paths", async () => {
    const fetchMock = mockFetchOnce(payload({ licenses: ["BSD-3-Clause"] }));
    global.fetch = fetchMock as never;

    await fetchVersionInfo(
      dep({ ecosystem: "Go", name: "github.com/gorilla/mux", version: "v1.8.0" }),
    );

    const url = fetchMock.mock.calls[0][0] as string;
    expect(url).toContain("github.com%2Fgorilla%2Fmux");
    expect(url).toContain("/versions/v1.8.0");
  });

  it("returns null on 404 without throwing", async () => {
    global.fetch = mockFetchOnce({}, 404) as never;
    expect(await fetchVersionInfo(dep())).toBeNull();
  });

  it("returns null when the request errors", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("network down")) as never;
    expect(await fetchVersionInfo(dep())).toBeNull();
  });

  it("returns null on a rate-limit response", async () => {
    global.fetch = mockFetchOnce({}, 429) as never;
    expect(await fetchVersionInfo(dep())).toBeNull();
  });
});

describe("caching", () => {
  it("serves a repeated lookup from cache", async () => {
    const fetchMock = mockFetchOnce(payload());
    global.fetch = fetchMock as never;

    await fetchVersionInfo(dep());
    await fetchVersionInfo(dep());

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("caches 404s so a missing version is not re-requested", async () => {
    const fetchMock = mockFetchOnce({}, 404);
    global.fetch = fetchMock as never;

    await fetchVersionInfo(dep());
    await fetchVersionInfo(dep());

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries transient failures on a later call", async () => {
    // 5xx must not be cached, otherwise an outage poisons the whole process.
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 503, json: async () => ({}) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => payload() });
    global.fetch = fetchMock as never;

    expect(await fetchVersionInfo(dep())).toBeNull();
    expect((await fetchVersionInfo(dep()))!.licenses).toEqual(["MIT"]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("keys the cache per version", async () => {
    const fetchMock = mockFetchOnce(payload());
    global.fetch = fetchMock as never;

    await fetchVersionInfo(dep({ version: "4.17.20" }));
    await fetchVersionInfo(dep({ version: "4.17.21" }));

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("fetchVersionInfoBatch", () => {
  it("returns results keyed by ecosystem:name@version", async () => {
    global.fetch = mockFetchOnce(payload()) as never;

    const result = await fetchVersionInfoBatch([dep()]);

    expect(result.get(dependencyKey(dep()))?.licenses).toEqual(["MIT"]);
  });

  it("filters out unsupported ecosystems before requesting", async () => {
    const fetchMock = mockFetchOnce(payload());
    global.fetch = fetchMock as never;

    const result = await fetchVersionInfoBatch([
      dep({ ecosystem: "Hex", name: "phoenix" }),
      dep({ ecosystem: "SwiftPM", name: "swift-nio" }),
    ]);

    expect(result.size).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns an empty map for no dependencies", async () => {
    const fetchMock = mockFetchOnce(payload());
    global.fetch = fetchMock as never;

    expect((await fetchVersionInfoBatch([])).size).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("keeps successful results when some lookups fail", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => payload() })
      .mockRejectedValueOnce(new Error("boom"));
    global.fetch = fetchMock as never;

    const result = await fetchVersionInfoBatch([
      dep({ name: "lodash" }),
      dep({ name: "express" }),
    ]);

    expect(result.size).toBe(1);
  });

  it("stops early when the scan is aborted", async () => {
    const fetchMock = mockFetchOnce(payload());
    global.fetch = fetchMock as never;
    const controller = new AbortController();
    controller.abort();

    const result = await fetchVersionInfoBatch([dep()], {
      signal: controller.signal,
    });

    expect(result.size).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
