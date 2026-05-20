import { describe, it, expect } from "vitest";
import { sastPatternScanner } from "./sast";
import { secretsPatternScanner } from "./secrets";
import { FindingDeduplicator, getScanners } from "./index";
import { applyQualityGates } from "./shared/quality-gates";
import { maskSecretValue, redactSensitiveText } from "./shared/evidence-redaction";
import { buildRootCauseKey, areRootCauseDuplicates } from "./shared/dedupe";
import { dastScanner } from "./dast";
import { containerScanner } from "./container";
import type { RawFinding } from "./types";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

function baseFinding(overrides: Partial<RawFinding>): RawFinding {
  return {
    scanner: "SAST_LLM",
    severity: "HIGH",
    title: "Test finding",
    description: "**Fix:** rotate keys",
    confidence: 0.9,
    filePath: "src/a.ts",
    startLine: 10,
    endLine: 12,
    metadata: { remediation: "Apply fix" },
    ...overrides,
  };
}

describe("scanner framework", () => {
  const llmOn = {
    enableLlmSast: true,
    enableLlmSecrets: true,
    dastEnabled: true,
  };

  it("FULL includes IaC and zero-day when LLM SAST is enabled", () => {
    const names = getScanners("FULL", llmOn).map((s) => s.name);
    expect(names).toContain("IAC");
    expect(names).toContain("ZERO_DAY");
  });

  it("IAC_ONLY and ZERO_DAY_ONLY run dedicated scanners", () => {
    expect(getScanners("IAC_ONLY", llmOn).map((s) => s.name)).toEqual(["IAC"]);
    expect(getScanners("ZERO_DAY_ONLY", llmOn).map((s) => s.name)).toEqual([
      "ZERO_DAY",
    ]);
  });

  it("INCREMENTAL runs SAST, SCA, and secrets (webhook PR scans)", () => {
    const names = getScanners("INCREMENTAL", llmOn).map((s) => s.name);
    expect(names).toContain("SAST_LLM");
    expect(names).toContain("SCA");
    expect(names).not.toContain("IAC");
    expect(names).not.toContain("ZERO_DAY");
  });

  it("pattern scanners never emit findings", async () => {
    const ctx = {
      workDir: "/tmp",
      fileList: ["src/index.ts"],
      scanType: "FULL",
      orgSettings: {
        llmProvider: "openai",
        llmBaseUrl: "",
        llmModel: "",
        enableLlmSast: true,
        enableLlmSecrets: true,
        osvApiUrl: "",
        vulnDbMode: "offline" as const,
      },
    };
    expect(await sastPatternScanner.scan(ctx)).toEqual([]);
    expect(await secretsPatternScanner.scan(ctx)).toEqual([]);
  });

  it("scanner failure does not become finding (DAST unavailable)", async () => {
    const findings = await dastScanner.scan({
      workDir: "/tmp",
      fileList: [],
      scanType: "DAST_ONLY",
      orgSettings: {
        llmProvider: "openai",
        llmBaseUrl: "",
        llmModel: "",
        enableLlmSast: false,
        enableLlmSecrets: false,
        osvApiUrl: "",
        vulnDbMode: "offline",
        dastEnabled: true,
        dastTargetUrl: "https://example.com",
        dastEndpoint: "http://127.0.0.1:1",
      },
    });
    expect(findings.find((f) => f.ruleId === "DAST-UNAVAILABLE")).toBeUndefined();
  });

  it("duplicate SAST and ZERO_DAY findings collapse", () => {
    const dedupe = new FindingDeduplicator();
    const sast = baseFinding({
      scanner: "SAST_LLM",
      cweId: "CWE-639",
      metadata: { weaknessClass: "IDOR", remediation: "fix" },
    });
    const zd = baseFinding({
      scanner: "ZERO_DAY",
      title: "IDOR in user API",
      cweId: "CWE-639",
      metadata: { weaknessClass: "IDOR", remediation: "fix" },
    });
    const first = dedupe.dedupe([sast]);
    const second = dedupe.dedupe([zd]);
    expect(first).toHaveLength(1);
    expect(second).toHaveLength(0);
    expect(dedupe.allFindings()).toHaveLength(1);
  });

  it("secret placeholders are suppressed by quality gates", () => {
    const gated = applyQualityGates([
      baseFinding({
        scanner: "SECRETS_LLM",
        title: "Example API key",
        description: "placeholder your_api_key here",
        confidence: 0.85,
        metadata: { remediation: "rotate" },
      }),
    ]);
    expect(gated).toHaveLength(0);
  });

  it("real-looking secret is masked", () => {
    const masked = maskSecretValue("sk-live-abcdefghijklmnop");
    expect(masked).toMatch(/^sk-l…/);
    expect(masked).not.toContain("abcdefghijklmnop");
  });

  it("SCA CVEs share root-cause key per package version", () => {
    const a = baseFinding({
      scanner: "SCA",
      cveId: "CVE-2024-1",
      metadata: {
        packageName: "lodash",
        packageVersion: "4.17.20",
        remediation: "upgrade",
      },
    });
    const b = baseFinding({
      scanner: "SCA",
      cveId: "CVE-2024-2",
      title: "Another CVE",
      metadata: {
        packageName: "lodash",
        packageVersion: "4.17.20",
        remediation: "upgrade",
      },
    });
    expect(buildRootCauseKey(a)).not.toBe(buildRootCauseKey(b));
    expect(areRootCauseDuplicates(a, b)).toBe(false);
  });

  it("malicious package heuristic rule IDs are blocked", () => {
    const gated = applyQualityGates([
      baseFinding({
        scanner: "MALICIOUS_PKG",
        ruleId: "MAL-NEW-PKG",
        metadata: { remediation: "remove" },
      }),
    ]);
    expect(gated).toHaveLength(0);
  });

  it("DAST evidence is redacted", () => {
    const raw =
      "Authorization: Bearer secret-token-12345\nCookie: session=abc";
    const redacted = redactSensitiveText(raw);
    expect(redacted).not.toContain("secret-token-12345");
    expect(redacted).toContain("[REDACTED]");
  });

  it("container unavailable scan returns no CVE inventory findings", async () => {
    const workDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "pepper-container-fw-"),
    );
    try {
      fs.writeFileSync(
        path.join(workDir, "Dockerfile"),
        "FROM alpine:3.19\n",
      );
      const findings = await containerScanner.scan({
        workDir,
        fileList: ["Dockerfile"],
        scanType: "CONTAINER_ONLY",
        orgSettings: {
          llmProvider: "openai",
          llmBaseUrl: "",
          llmModel: "",
          enableLlmSast: false,
          enableLlmSecrets: false,
          osvApiUrl: "",
          vulnDbMode: "offline",
        },
      });
      expect(
        findings.filter((f) => f.ruleId === "CONTAINER-INVENTORY"),
      ).toHaveLength(0);
      expect(
        findings.filter((f) => f.ruleId === "CONTAINER-SCAN-FAILED"),
      ).toHaveLength(0);
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("all gated findings require remediation and confidence", () => {
    const gated = applyQualityGates([
      baseFinding({ metadata: { remediation: "patch it" } }),
      baseFinding({
        confidence: 0.5,
        metadata: { remediation: "patch" },
      }),
      baseFinding({
        description: "no fix mentioned",
        metadata: {},
      }),
    ]);
    expect(gated).toHaveLength(1);
    expect(gated[0].confidence).toBeGreaterThanOrEqual(0.8);
  });
});
