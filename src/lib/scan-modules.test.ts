import { describe, expect, it } from "vitest";
import {
  SCAN_MODULE_IDS,
  normalizeScanSelection,
  parseRescanBody,
  scanIncludesModule,
  scanModeLabel,
} from "./scan-types";
import { getScanners } from "@/scanners";
import {
  SCAN_MODULES_KEY,
  computeScanProgress,
  isScannerProgressKey,
  progressWithScanModules,
  scanModulesFromProgress,
} from "./scan-progress";

const llmOn = { enableLlmSast: true, enableLlmSecrets: true };

describe("normalizeScanSelection", () => {
  it("keeps the scan type when no modules are picked", () => {
    expect(normalizeScanSelection("SCA_ONLY")).toEqual({ scanType: "SCA_ONLY", scanModules: [] });
  });

  it("maps one module to its _ONLY type and all modules to FULL", () => {
    expect(normalizeScanSelection("FULL", ["SECRETS"])).toEqual({
      scanType: "SECRETS_ONLY",
      scanModules: [],
    });
    expect(normalizeScanSelection("FULL", [...SCAN_MODULE_IDS])).toEqual({
      scanType: "FULL",
      scanModules: [],
    });
  });

  it("stores a combination as FULL plus modules, in display order", () => {
    expect(normalizeScanSelection("FULL", ["SECRETS", "SAST"])).toEqual({
      scanType: "FULL",
      scanModules: ["SAST", "SECRETS"],
    });
  });

  it("keeps PR Diff and narrows it by modules", () => {
    expect(normalizeScanSelection("INCREMENTAL", ["SCA"])).toEqual({
      scanType: "INCREMENTAL",
      scanModules: ["SCA"],
    });
  });
});

describe("scanModeLabel", () => {
  it("names every mode in words", () => {
    expect(scanModeLabel("FULL")).toBe("All scanners");
    expect(scanModeLabel("INCREMENTAL")).toBe("PR Diff");
    expect(scanModeLabel("K8S_ONLY")).toBe("Kubernetes");
    expect(scanModeLabel("ZERO_DAY_ONLY")).toBe("Zero-day");
    expect(scanModeLabel("FULL", ["SAST", "SECRETS"])).toBe("SAST + Secrets");
    expect(scanModeLabel("INCREMENTAL", ["SCA"])).toBe("PR Diff · SCA");
  });
});

describe("scanner selection with modules", () => {
  it("runs only the chosen modules' scanners", () => {
    const names = getScanners("FULL", llmOn, ["SAST", "SECRETS"]).map((s) => s.name);
    expect(names).toContain("SAST_LLM");
    expect(names).toContain("SECRETS_PATTERN");
    for (const n of ["SCA", "MALICIOUS_PKG", "IAC", "ZERO_DAY", "CONTAINER", "K8S"]) {
      expect(names).not.toContain(n);
    }
  });

  it("matches the old behaviour for single-module types", () => {
    expect(scanIncludesModule("SAST_ONLY", [], "SAST")).toBe(true);
    expect(scanIncludesModule("SAST_ONLY", [], "SCA")).toBe(false);
    expect(scanIncludesModule("FULL", [], "K8S")).toBe(true);
  });
});

describe("parseRescanBody scanModules", () => {
  it("accepts known modules and rejects unknown ones", () => {
    expect(parseRescanBody(JSON.stringify({ scanType: "FULL", scanModules: ["SAST", "SCA"] }))).toEqual({
      ok: true,
      scanType: "FULL",
      scanModules: ["SAST", "SCA"],
    });
    expect(parseRescanBody(JSON.stringify({ scanModules: ["NOPE"] })).ok).toBe(false);
  });
});

describe("scanner combination stored on scannerProgress", () => {
  it("round-trips through the reserved key", () => {
    const progress = progressWithScanModules(["SAST", "SECRETS"]);
    expect(progress).toEqual({ [SCAN_MODULES_KEY]: ["SAST", "SECRETS"] });
    expect(scanModulesFromProgress(progress)).toEqual(["SAST", "SECRETS"]);
  });

  it("is empty for scans without a combination", () => {
    expect(progressWithScanModules([])).toEqual({});
    expect(scanModulesFromProgress(null)).toEqual([]);
    expect(scanModulesFromProgress({ SAST_LLM: { status: "DONE" } })).toEqual([]);
  });

  it("is not treated as a scanner in progress", () => {
    expect(isScannerProgressKey(SCAN_MODULES_KEY)).toBe(false);
    const progress = {
      ...progressWithScanModules(["SAST", "SCA"]),
      SAST_LLM: { status: "DONE" },
    } as unknown as Parameters<typeof computeScanProgress>[0];
    expect(computeScanProgress(progress, "RUNNING")).toBe(
      computeScanProgress({ SAST_LLM: { status: "DONE" } }, "RUNNING"),
    );
  });
});
