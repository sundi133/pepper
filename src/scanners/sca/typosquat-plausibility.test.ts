import { describe, it, expect } from "vitest";
import {
  isPlausibleTyposquat,
  normalisePackageName,
  editDistance,
} from "./typosquat-plausibility";

const plausible = (
  packageName: string,
  similarTo: string,
  ecosystem?: string,
) => isPlausibleTyposquat({ packageName, similarTo, ecosystem }).plausible;

describe("the mcp false positive", () => {
  // PyPI's `mcp` is the official Model Context Protocol SDK published by
  // Anthropic (repository: modelcontextprotocol/python-sdk). It was reported as
  // a typosquat of npm's @modelcontextprotocol/sdk because "mcp" abbreviates the
  // project name — semantic association, not typosquatting.
  it("rejects mcp as a typosquat of @modelcontextprotocol/sdk", () => {
    const result = isPlausibleTyposquat({
      packageName: "mcp",
      ecosystem: "PyPI",
      similarTo: "@modelcontextprotocol/sdk",
    });
    expect(result.plausible).toBe(false);
  });

  it("explains why, rather than failing silently", () => {
    const result = isPlausibleTyposquat({
      packageName: "mcp",
      ecosystem: "PyPI",
      similarTo: "@modelcontextprotocol/sdk",
    });
    expect(result.reason).toBeTruthy();
  });
});

describe("cross-registry claims", () => {
  it("rejects a claim spanning two ecosystems", () => {
    expect(
      isPlausibleTyposquat({
        packageName: "requests",
        ecosystem: "PyPI",
        similarTo: "requests",
        similarToEcosystem: "npm",
      }).plausible,
    ).toBe(false);
  });

  it("rejects a scoped npm target compared against a non-npm package", () => {
    expect(plausible("sdk", "@scope/sdk", "PyPI")).toBe(false);
  });

  it("still allows a same-ecosystem claim", () => {
    expect(
      isPlausibleTyposquat({
        packageName: "reqeusts",
        ecosystem: "PyPI",
        similarTo: "requests",
        similarToEcosystem: "PyPI",
      }).plausible,
    ).toBe(true);
  });

  it("treats equivalent ecosystem labels as the same registry", () => {
    expect(
      isPlausibleTyposquat({
        packageName: "reqeusts",
        ecosystem: "pip",
        similarTo: "requests",
        similarToEcosystem: "PyPI",
      }).plausible,
    ).toBe(true);
  });
});

describe("real typosquat patterns are still caught", () => {
  it("catches character substitution", () => {
    expect(plausible("reqeusts", "requests", "PyPI")).toBe(true);
    expect(plausible("lodahs", "lodash", "npm")).toBe(true);
  });

  it("catches a single character omission or addition", () => {
    expect(plausible("lodas", "lodash", "npm")).toBe(true);
    expect(plausible("expres", "express", "npm")).toBe(true);
  });

  it("catches combosquatting with a common affix", () => {
    expect(plausible("lodash-js", "lodash", "npm")).toBe(true);
    expect(plausible("requests-python", "requests", "PyPI")).toBe(true);
  });

  it("catches separator confusion where the registry allows it", () => {
    // npm treats these as distinct names, so one can squat the other.
    expect(plausible("lodashes", "lodash-es", "npm")).toBe(true);
  });

  it("does not flag separator variants on PyPI", () => {
    // PEP 503 normalises separators and case, so both names resolve to one
    // package and neither can squat the other.
    expect(plausible("python_dateutil", "python-dateutil", "PyPI")).toBe(false);
  });
});

describe("legitimate packages are not flagged", () => {
  it("does not flag an abbreviation of a longer project name", () => {
    expect(plausible("mcp", "modelcontextprotocol", "PyPI")).toBe(false);
    expect(plausible("k8s", "kubernetes", "npm")).toBe(false);
  });

  it("does not flag a package against itself", () => {
    expect(plausible("lodash", "lodash", "npm")).toBe(false);
    expect(plausible("@scope/sdk", "sdk", "npm")).toBe(false);
  });

  it("does not flag unrelated names", () => {
    expect(plausible("express", "lodash", "npm")).toBe(false);
    expect(plausible("numpy", "requests", "PyPI")).toBe(false);
  });

  it("does not flag a legitimate extension of a popular package", () => {
    // These share a prefix but the extra part is not a squatting affix.
    expect(plausible("express-validator", "express", "npm")).toBe(false);
    expect(plausible("eslint-config-airbnb", "eslint", "npm")).toBe(false);
  });

  it("handles a missing name without throwing", () => {
    expect(plausible("", "lodash", "npm")).toBe(false);
    expect(plausible("lodash", "", "npm")).toBe(false);
  });
});

describe("normalisePackageName", () => {
  it("strips npm scopes", () => {
    expect(normalisePackageName("@modelcontextprotocol/sdk")).toBe("sdk");
  });

  it("strips maven group ids", () => {
    expect(normalisePackageName("com.fasterxml:jackson-databind")).toBe(
      "jacksondatabind",
    );
  });

  it("removes separators and lowercases", () => {
    expect(normalisePackageName("Python-Date_Util")).toBe("pythondateutil");
  });
});

describe("editDistance", () => {
  it("computes known distances", () => {
    expect(editDistance("requests", "requests")).toBe(0);
    expect(editDistance("reqeusts", "requests")).toBe(2);
    expect(editDistance("", "abc")).toBe(3);
  });
});
