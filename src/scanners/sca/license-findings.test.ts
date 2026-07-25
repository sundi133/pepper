import { describe, it, expect } from "vitest";
import { attachLicenses, buildLicenseFindings } from "./license-findings";
import { dependencyKey, type DepsDevVersionInfo } from "./deps-dev-client";
import type { Dependency } from "../types";
import type { LicensePolicy } from "./license-policy";

const policy: LicensePolicy = {
  deny: ["AGPL-*", "GPL-*"],
  warn: ["LGPL-*", "MPL-*"],
  flagUnknown: false,
};

function dep(over: Partial<Dependency> = {}): Dependency {
  return {
    name: "somepkg",
    version: "1.0.0",
    ecosystem: "npm",
    sourceFile: "package.json",
    ...over,
  };
}

function info(over: Partial<DepsDevVersionInfo> = {}): DepsDevVersionInfo {
  return {
    licenses: ["MIT"],
    sourceRepo: "https://github.com/example/somepkg",
    isDeprecated: false,
    hasSlsaProvenance: false,
    hasAttestations: false,
    ...over,
  };
}

function infoMap(pairs: Array<[Dependency, DepsDevVersionInfo]>) {
  return new Map(pairs.map(([d, i]) => [dependencyKey(d), i]));
}

describe("attachLicenses", () => {
  it("attaches declared licenses to matching dependencies", () => {
    const d = dep();
    const result = attachLicenses([d], infoMap([[d, info({ licenses: ["MIT"] })]]));
    expect(result[0].licenses).toEqual(["MIT"]);
  });

  it("leaves dependencies untouched when there is no metadata", () => {
    const d = dep();
    const result = attachLicenses([d], new Map());
    expect(result[0].licenses).toBeUndefined();
    expect(result[0]).toBe(d);
  });

  it("does not attach an empty license list", () => {
    const d = dep();
    const result = attachLicenses([d], infoMap([[d, info({ licenses: [] })]]));
    expect(result[0].licenses).toBeUndefined();
  });

  it("does not mutate the input dependencies", () => {
    const d = dep();
    attachLicenses([d], infoMap([[d, info()]]));
    expect(d.licenses).toBeUndefined();
  });
});

describe("buildLicenseFindings", () => {
  it("emits no finding for a permissively licensed dependency", () => {
    const d = dep();
    const findings = buildLicenseFindings(
      [d],
      infoMap([[d, info({ licenses: ["MIT"] })]]),
      new Set(),
      policy,
    );
    expect(findings).toEqual([]);
  });

  it("emits a HIGH finding for a denied license", () => {
    const d = dep({ name: "copyleft-lib" });
    const findings = buildLicenseFindings(
      [d],
      infoMap([[d, info({ licenses: ["GPL-3.0"] })]]),
      new Set(["copyleft-lib"]),
      policy,
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].ruleId).toBe("LICENSE-DENIED");
    expect(findings[0].cweId).toBe("CWE-1357");
    expect(findings[0].title).toContain("copyleft-lib");
    expect(findings[0].metadata?.licenseVerdict).toBe("denied");
    expect(findings[0].metadata?.licenseExpression).toBe("GPL-3.0");
    expect(findings[0].metadata?.directDependency).toBe(true);
  });

  it("emits a LOW finding for a weak-copyleft license", () => {
    const d = dep();
    const findings = buildLicenseFindings(
      [d],
      infoMap([[d, info({ licenses: ["MPL-2.0"] })]]),
      new Set(),
      policy,
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("LOW");
    expect(findings[0].ruleId).toBe("LICENSE-WARN");
  });

  it("does not flag a dual license where one branch is allowed", () => {
    // Substring matching on "GPL" would produce a false positive here.
    const d = dep();
    const findings = buildLicenseFindings(
      [d],
      infoMap([[d, info({ licenses: ["BSD-3-Clause OR GPL-2.0"] })]]),
      new Set(),
      policy,
    );
    expect(findings).toEqual([]);
  });

  it("keeps HIGH severity for a transitive dependency", () => {
    // Copyleft obligations bind regardless of dependency depth.
    const d = dep({ name: "deep-lib", sourceFile: "package-lock.json" });
    const findings = buildLicenseFindings(
      [d],
      infoMap([[d, info({ licenses: ["AGPL-3.0"] })]]),
      new Set(), // not a direct dependency
      policy,
    );

    expect(findings[0].severity).toBe("HIGH");
    expect(findings[0].metadata?.directDependency).toBe(false);
    expect(findings[0].description).toContain("transitive dependency");
  });

  it("stays silent when there is no metadata for a dependency", () => {
    // Unsupported ecosystem or a failed lookup is not a policy violation.
    const findings = buildLicenseFindings(
      [dep({ ecosystem: "Hex" })],
      new Map(),
      new Set(),
      policy,
    );
    expect(findings).toEqual([]);
  });

  it("does not flag unknown licenses by default", () => {
    const d = dep();
    const findings = buildLicenseFindings(
      [d],
      infoMap([[d, info({ licenses: ["non-standard"] })]]),
      new Set(),
      policy,
    );
    expect(findings).toEqual([]);
  });

  it("flags unknown licenses as INFO when the policy opts in", () => {
    const d = dep();
    const findings = buildLicenseFindings(
      [d],
      infoMap([[d, info({ licenses: ["non-standard"] })]]),
      new Set(),
      { ...policy, flagUnknown: true },
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("INFO");
    expect(findings[0].ruleId).toBe("LICENSE-UNKNOWN");
  });

  it("points the finding at the manifest that introduced the dependency", () => {
    const d = dep({ sourceFile: "frontend/package.json" });
    const findings = buildLicenseFindings(
      [d],
      infoMap([[d, info({ licenses: ["GPL-3.0"] })]]),
      new Set(),
      policy,
    );
    expect(findings[0].filePath).toBe("frontend/package.json");
  });

  it("records the policy pattern and remediation for triage", () => {
    const d = dep();
    const findings = buildLicenseFindings(
      [d],
      infoMap([[d, info({ licenses: ["GPL-3.0"] })]]),
      new Set(),
      policy,
    );

    expect(findings[0].metadata?.licensePolicyPattern).toBe("GPL-*");
    expect(findings[0].metadata?.evidenceSource).toBe("deps.dev");
    expect(String(findings[0].metadata?.remediation)).toContain("allow list");
  });

  it("emits one finding per violating dependency", () => {
    const a = dep({ name: "a" });
    const b = dep({ name: "b" });
    const c = dep({ name: "c" });
    const findings = buildLicenseFindings(
      [a, b, c],
      infoMap([
        [a, info({ licenses: ["GPL-3.0"] })],
        [b, info({ licenses: ["MIT"] })],
        [c, info({ licenses: ["AGPL-3.0"] })],
      ]),
      new Set(),
      policy,
    );

    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.metadata?.packageName)).toEqual(["a", "c"]);
  });
});
