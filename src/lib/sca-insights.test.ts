import { describe, it, expect } from "vitest";
import {
  advisoryUrl,
  cweUrl,
  exploitPriority,
  fixGuidance,
  impactForWeakness,
  upgradeRisk,
} from "./sca-insights";

describe("impactForWeakness", () => {
  it("maps a CWE to a specific attacker outcome", () => {
    expect(impactForWeakness("CWE-79")?.outcome).toMatch(/JavaScript/);
    expect(impactForWeakness("CWE-89")?.outcome).toMatch(/database/);
    expect(impactForWeakness("CWE-1321")?.outcome).toMatch(/every object/);
  });

  it("falls back to the advisory text, then null", () => {
    expect(impactForWeakness(null, "Reflected XSS in server responses")?.outcome).toMatch(/JavaScript/);
    expect(impactForWeakness("CWE-99999", "something odd")).toBeNull();
  });
});

describe("upgradeRisk", () => {
  it("classifies semver jumps", () => {
    expect(upgradeRisk("1.168.32", "1.168.60")).toBe("patch");
    expect(upgradeRisk("1.2.3", "1.4.0")).toBe("minor");
    expect(upgradeRisk("1.2.3", "2.0.0")).toBe("major");
    expect(upgradeRisk("0.3.1", "0.4.0")).toBe("major");
    expect(upgradeRisk("v1.0.0", "1.0.1")).toBe("patch");
    expect(upgradeRisk(undefined, "1.0.0")).toBe("unknown");
    expect(upgradeRisk("abc", "1.0.0")).toBe("unknown");
  });
});

describe("exploitPriority", () => {
  it("puts known-exploited vulnerabilities first regardless of severity", () => {
    const v = exploitPriority({ severity: "MEDIUM", cisaKevListed: true });
    expect(v.priority).toBe("act-now");
    expect(v.reasons[0]).toMatch(/CISA KEV/);
  });

  it("treats a high EPSS as act-now and a moderate one as prioritize", () => {
    expect(exploitPriority({ severity: "LOW", epssScore: 0.6 }).priority).toBe("act-now");
    expect(exploitPriority({ severity: "LOW", epssScore: 0.2 }).priority).toBe("prioritize");
  });

  it("uses severity when there's no exploitation signal", () => {
    expect(exploitPriority({ severity: "CRITICAL" }).priority).toBe("prioritize");
    expect(exploitPriority({ severity: "HIGH", imported: true }).priority).toBe("prioritize");
    expect(exploitPriority({ severity: "HIGH" }).priority).toBe("schedule");
    expect(exploitPriority({ severity: "LOW" }).priority).toBe("track");
  });

  it("lowers urgency when the package isn't imported, unless exploited", () => {
    expect(exploitPriority({ severity: "CRITICAL", imported: false }).priority).toBe("schedule");
    expect(exploitPriority({ severity: "LOW", cisaKevListed: true, imported: false }).priority).toBe(
      "act-now",
    );
  });
});

describe("fixGuidance", () => {
  it("gives an install command for a direct npm dependency", () => {
    expect(
      fixGuidance({ ecosystem: "npm", packageName: "zod", fixVersion: "3.22.3", directDependency: true }),
    ).toEqual({ command: "npm install zod@3.22.3" });
  });

  it("gives a parent update and an override for a transitive npm dependency", () => {
    const g = fixGuidance({
      ecosystem: "npm",
      packageName: "cookie",
      fixVersion: "0.7.0",
      directDependency: false,
      introducedBy: "express",
    });
    expect(g.command).toBe("npm update express");
    expect(JSON.parse(g.override!.snippet)).toEqual({ overrides: { cookie: "0.7.0" } });
    expect(g.note).toMatch(/through express/);
  });

  it("covers other ecosystems and the no-fix case", () => {
    expect(fixGuidance({ ecosystem: "Go", packageName: "golang.org/x/net", fixVersion: "0.23.0" }).command).toBe(
      "go get golang.org/x/net@v0.23.0 && go mod tidy",
    );
    expect(
      fixGuidance({ ecosystem: "Maven", packageName: "org.yaml:snakeyaml", fixVersion: "2.0" }).override?.snippet,
    ).toContain("<artifactId>snakeyaml</artifactId>");
    expect(fixGuidance({ ecosystem: "PyPI", packageName: "jinja2", fixVersion: "3.1.4", directDependency: false }).override)
      .toEqual({ file: "constraints.txt", snippet: "jinja2>=3.1.4" });
    expect(fixGuidance({ ecosystem: "npm", packageName: "x" }).note).toMatch(/No patched version/);
  });
});

describe("links", () => {
  it("builds advisory and CWE URLs", () => {
    expect(advisoryUrl("GHSA-qx66-fv34-fjm8")).toBe("https://github.com/advisories/GHSA-qx66-fv34-fjm8");
    expect(advisoryUrl("CVE-2024-1")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2024-1");
    expect(advisoryUrl("PYSEC-2024-1")).toBe("https://osv.dev/vulnerability/PYSEC-2024-1");
    expect(cweUrl("CWE-79")).toBe("https://cwe.mitre.org/data/definitions/79.html");
  });
});
