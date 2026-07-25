import { describe, it, expect } from "vitest";
import { generateCycloneDx, generateSpdx } from "./sbom-generator";

const deps = [
  { name: "lodash", version: "4.17.21", ecosystem: "npm" },
  {
    name: "left-pad",
    version: "1.3.0",
    ecosystem: "npm",
    isDev: true,
  },
  {
    name: "com.fasterxml.jackson.core:jackson-databind",
    version: "2.15.2",
    ecosystem: "maven",
  },
];

const meta = {
  projectName: "demo-app",
  projectVersion: "0.1.0",
  scanId: "scan_abc",
  commitSha: "deadbeef",
  branch: "main",
  generatedAt: "2026-05-17T00:00:00.000Z",
};

describe("generateCycloneDx", () => {
  it("emits a valid 1.5 BOM with all components", () => {
    const out = JSON.parse(generateCycloneDx(deps, meta));
    expect(out.bomFormat).toBe("CycloneDX");
    expect(out.specVersion).toBe("1.5");
    expect(out.serialNumber).toMatch(/^urn:uuid:/);
    expect(out.metadata.tools[0].vendor).toBe("Pepper");
    expect(out.metadata.component.name).toBe("demo-app");
    expect(out.components).toHaveLength(3);
    const purls = out.components.map((c: { purl: string }) => c.purl);
    expect(purls).toContain("pkg:npm/lodash@4.17.21");
    expect(purls.some((p: string) => p.startsWith("pkg:maven/com.fasterxml"))).toBe(
      true,
    );
    const leftPad = out.components.find(
      (c: { name: string }) => c.name === "left-pad",
    );
    expect(leftPad.scope).toBe("optional");
  });
});

describe("generateSpdx", () => {
  it("emits SPDX 2.3 JSON with root + per-package relationships", () => {
    const out = JSON.parse(generateSpdx(deps, meta));
    expect(out.spdxVersion).toBe("SPDX-2.3");
    expect(out.SPDXID).toBe("SPDXRef-DOCUMENT");
    expect(out.packages.length).toBe(deps.length + 1);
    const root = out.packages[0];
    expect(root.SPDXID).toBe("SPDXRef-Package-Root");
    expect(out.relationships[0]).toMatchObject({
      spdxElementId: "SPDXRef-DOCUMENT",
      relatedSpdxElement: "SPDXRef-Package-Root",
      relationshipType: "DESCRIBES",
    });
    const devRel = out.relationships.find(
      (r: { relationshipType: string }) =>
        r.relationshipType === "DEV_DEPENDENCY_OF",
    );
    expect(devRel).toBeDefined();
    const lp = out.packages.find(
      (p: { name: string }) => p.name === "left-pad",
    );
    expect(lp.externalRefs[0].referenceType).toBe("purl");
  });
});

// ─── License reporting ───────────────────────────────────────────────────────
// Licences resolved from deps.dev must reach both SBOM formats; previously every
// package was emitted as NOASSERTION regardless of its declared licence.

const licensedDeps = [
  { name: "lodash", version: "4.17.21", ecosystem: "npm", licenses: ["MIT"] },
  { name: "serde", version: "1.0.197", ecosystem: "crates.io", licenses: ["Apache-2.0 OR MIT"] },
  { name: "weird", version: "1.0.0", ecosystem: "npm", licenses: ["non-standard"] },
  { name: "unknown-lic", version: "1.0.0", ecosystem: "npm" },
];

function component(out: { components: Array<{ name: string }> }, name: string) {
  return out.components.find((c) => c.name === name) as Record<string, unknown>;
}

describe("generateCycloneDx — licenses", () => {
  it("emits a bare SPDX ID as a license object", () => {
    const out = JSON.parse(generateCycloneDx(licensedDeps, meta));
    expect(component(out, "lodash").licenses).toEqual([{ license: { id: "MIT" } }]);
  });

  it("emits a compound SPDX expression as an expression", () => {
    // CycloneDX requires `expression` rather than a license id for AND/OR forms.
    const out = JSON.parse(generateCycloneDx(licensedDeps, meta));
    expect(component(out, "serde").licenses).toEqual([
      { expression: "Apache-2.0 OR MIT" },
    ]);
  });

  it("emits an unmappable license as a free-text name, not a bogus ID", () => {
    const out = JSON.parse(generateCycloneDx(licensedDeps, meta));
    expect(component(out, "weird").licenses).toEqual([
      { license: { name: "non-standard" } },
    ]);
  });

  it("omits the licenses field entirely when no license is known", () => {
    const out = JSON.parse(generateCycloneDx(licensedDeps, meta));
    expect(component(out, "unknown-lic").licenses).toBeUndefined();
  });
});

describe("generateSpdx — licenses", () => {
  function pkg(out: { packages: Array<{ name: string }> }, name: string) {
    return out.packages.find((p) => p.name === name) as Record<string, string>;
  }

  it("reports the declared license", () => {
    const out = JSON.parse(generateSpdx(licensedDeps, meta));
    expect(pkg(out, "lodash").licenseDeclared).toBe("MIT");
    expect(pkg(out, "serde").licenseDeclared).toBe("Apache-2.0 OR MIT");
  });

  it("leaves licenseConcluded as NOASSERTION since we do not audit source", () => {
    const out = JSON.parse(generateSpdx(licensedDeps, meta));
    expect(pkg(out, "lodash").licenseConcluded).toBe("NOASSERTION");
  });

  it("falls back to NOASSERTION for unknown and unmappable licenses", () => {
    const out = JSON.parse(generateSpdx(licensedDeps, meta));
    expect(pkg(out, "unknown-lic").licenseDeclared).toBe("NOASSERTION");
    expect(pkg(out, "weird").licenseDeclared).toBe("NOASSERTION");
  });

  it("still emits NOASSERTION for dependencies with no license data at all", () => {
    const out = JSON.parse(generateSpdx(deps, meta));
    for (const p of out.packages) {
      expect(p.licenseDeclared).toBe("NOASSERTION");
    }
  });
});
