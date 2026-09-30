import { describe, expect, it } from "vitest";
import { compareVersions, cvss3BaseScore, osvFixVersion, osvSeverity } from "./osv-severity";
import { swiftPackageResolvedParser, swiftPackageUrlName } from "./parsers/swift-package";
import { purlFor } from "./sbom-generator";

describe("cvss3BaseScore", () => {
  // Expected values are the published NVD base scores for these vectors.
  it.each([
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0], // Log4Shell CVE-2021-44228
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8],
    ["CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2], // lodash CVE-2021-23337
    ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4], // typical stored XSS
    ["CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5],
    ["CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1],
    ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0],
  ])("%s → %s", (vector, score) => {
    expect(cvss3BaseScore(vector)).toBe(score);
  });

  it("rejects non-v3 or malformed vectors", () => {
    expect(cvss3BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")).toBeNull();
    expect(cvss3BaseScore("AV:N/AC:L/Au:N/C:P/I:P/A:P")).toBeNull();
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L")).toBeNull();
  });
});

describe("osvSeverity", () => {
  it("prefers the computed CVSS v3 score", () => {
    expect(
      osvSeverity({
        id: "GHSA-35jh-r3h4-6jhm",
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
        database_specific: { severity: "CRITICAL" },
      }),
    ).toEqual({ severity: "HIGH", cvssScore: 7.2 });
  });

  it("falls back to the advisory label (MODERATE → MEDIUM), then MEDIUM", () => {
    expect(osvSeverity({ id: "x", severity: [{ type: "CVSS_V4", score: "CVSS:4.0/…" }], database_specific: { severity: "MODERATE" } }).severity).toBe("MEDIUM");
    expect(osvSeverity({ id: "x", affected: [{ ecosystem_specific: { severity: "high" } }] }).severity).toBe("HIGH");
    expect(osvSeverity({ id: "x" })).toEqual({ severity: "MEDIUM", cvssScore: null });
  });
});

describe("osvFixVersion", () => {
  const vuln = {
    id: "GHSA-x",
    affected: [
      { package: { name: "other", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "9.9.9" }] }] },
      {
        package: { name: "lodash", ecosystem: "npm" },
        ranges: [
          { type: "SEMVER", events: [{ introduced: "3.0.0" }, { fixed: "3.10.2" }, { introduced: "4.0.0" }, { fixed: "4.17.21" }] },
          { type: "GIT", events: [{ introduced: "0" }, { fixed: "abc123" }] },
        ],
      },
    ],
  };

  it("uses this package's ranges and the lowest fix above the installed version", () => {
    expect(osvFixVersion(vuln, { name: "lodash", version: "4.17.20", ecosystem: "npm" })).toBe("4.17.21");
    expect(osvFixVersion(vuln, { name: "lodash", version: "3.5.0", ecosystem: "npm" })).toBe("3.10.2");
  });

  it("normalises PyPI names and returns undefined when no fix exists", () => {
    const py = { id: "p", affected: [{ package: { name: "Django-Rest", ecosystem: "PyPI" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0" }] }] }] };
    expect(osvFixVersion(py, { name: "django_rest", version: "1.0", ecosystem: "PyPI" })).toBe("2.0");
    expect(osvFixVersion({ id: "n", affected: [{ package: { name: "a" }, ranges: [{ events: [{ introduced: "0" }] }] }] }, { name: "a", version: "1", ecosystem: "npm" })).toBeUndefined();
  });
});

describe("compareVersions", () => {
  it("orders numerically and puts pre-releases before releases", () => {
    expect(compareVersions("1.2.10", "1.2.9")).toBe(1);
    expect(compareVersions("v2.0.0", "2.0.0")).toBe(0);
    expect(compareVersions("2.0.0-rc1", "2.0.0")).toBe(-1);
    expect(compareVersions("2.0", "2.0.1")).toBe(-1);
  });
});

describe("Swift packages", () => {
  it("derives OSV SwiftURL names from repository URLs", () => {
    expect(swiftPackageUrlName("https://github.com/vapor/vapor.git")).toBe("github.com/vapor/vapor");
    expect(swiftPackageUrlName("git@github.com:apple/swift-nio.git")).toBe("github.com/apple/swift-nio");
    expect(swiftPackageUrlName("vapor")).toBeNull();
  });

  it("parses Package.resolved v1 and v2 into SwiftURL dependencies", () => {
    const v2 = JSON.stringify({ pins: [{ identity: "vapor", location: "https://github.com/vapor/vapor.git", state: { version: "4.0.0" } }], version: 2 });
    const v1 = JSON.stringify({ object: { pins: [{ package: "NIO", repositoryURL: "https://github.com/apple/swift-nio.git", state: { version: "2.30.0" } }] }, version: 1 });
    expect(swiftPackageResolvedParser.parse(v2, "Package.resolved")).toEqual([{ name: "github.com/vapor/vapor", version: "4.0.0", ecosystem: "SwiftURL" }]);
    expect(swiftPackageResolvedParser.parse(v1, "Package.resolved")[0]).toMatchObject({ name: "github.com/apple/swift-nio", ecosystem: "SwiftURL" });
  });

  it("emits a spec-shaped swift purl", () => {
    expect(purlFor({ name: "github.com/vapor/vapor", version: "4.0.0", ecosystem: "SwiftURL" })).toBe("pkg:swift/github.com/vapor/vapor@4.0.0");
  });
});
