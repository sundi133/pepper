import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { compiledScanConfig } from "./config";
import type { ToolRunner } from "./decompile";
import { runCompiledScan } from "./index";
import { discoverArtifacts } from "./artifacts";
import { zipFile } from "./test-fixtures";

const silentLog = { info: vi.fn(), warn: vi.fn() } as never;

let workDir: string;
beforeEach(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-ipa-"));
});
afterEach(() => {
  fs.rmSync(workDir, { recursive: true, force: true });
});

function put(rel: string, content: Buffer | string, root = workDir) {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content);
}

const config = () => compiledScanConfig();

// A decompiler runner that must never be invoked for an .ipa (iOS is handled
// in-process, with no spawned tool).
const noRunner: ToolRunner = async () => {
  throw new Error("no decompiler should be spawned for an .ipa");
};

describe("compiled-scan iOS .ipa dispatch", () => {
  it("recognizes a .ipa as an 'ios' artifact", () => {
    // A valid (stored) zip so the discovery header/central-directory checks pass.
    put("App.ipa", zipFile({ "Payload/Demo.app/Info.plist": "bplist00" }));
    const { artifacts } = discoverArtifacts({
      workDir,
      candidates: ["App.ipa"],
      sourceFiles: [],
      maxArtifactBytes: 100 * 1024 * 1024,
      maxArtifacts: 10,
      filter: { skipThirdParty: true, excludePackages: [], includePackages: [] },
    });
    expect(artifacts).toHaveLength(1);
    expect(artifacts[0].kind).toBe("ios");
  });

  it("extracts Info.plist metadata in-process without a decompiler", async () => {
    put("App.ipa", zipFile({ "Payload/Demo.app/Info.plist": "bplist00" }));

    // Injected unzip lays down a Payload/.app tree (no reliance on a real
    // unzip binary or CRC-correct fixtures). extractIpaMetadata reads it.
    const unzip = (_archive: string, destDir: string) => {
      const app = path.join(destDir, "Payload", "Demo.app");
      fs.mkdirSync(app, { recursive: true });
      fs.writeFileSync(
        path.join(app, "Info.plist"),
        Buffer.from("bplist00 CFBundleIdentifier com.demo NSAppTransportSecurity"),
      );
      fs.writeFileSync(path.join(app, "Demo"), Buffer.from("https://api.demo.example MachOstrings"));
    };

    const outcome = await runCompiledScan({
      workDir,
      fileList: ["App.ipa"],
      scanType: "FULL",
      config: config(),
      runner: noRunner,
      unzip,
      log: silentLog,
    });

    expect(outcome.summary.decompiled).toBe(1);
    expect(outcome.summary.failed).toBe(0);
    expect(outcome.summary.artifacts[0].tool).toBe("ipa-extract");
    // Info.plist (the mobile scanner's iOS anchor) and the executable strings
    // are added to the scan's file list.
    const names = outcome.files.map((f) => path.posix.basename(f));
    expect(names).toContain("Info.plist");
    expect(names).toContain("executable.strings.txt");
    // Every returned file exists on disk for the scanners to read.
    for (const f of outcome.files) {
      expect(fs.existsSync(path.join(workDir, f))).toBe(true);
    }
    // The path map knows the .ipa the files came from.
    const anchor = outcome.files.find((f) => f.endsWith("/Info.plist"));
    expect(anchor && outcome.pathMap.mapFinding({ scanner: "SAST_LLM", severity: "LOW", title: "t", description: "", filePath: anchor }).filePath)
      .toMatch(/App\.ipa!\//);
  });

  it("records a failure when the .ipa has no Payload/*.app", async () => {
    put("App.ipa", zipFile({ "junk.txt": "nothing useful" }));
    const unzip = (_archive: string, destDir: string) => {
      fs.writeFileSync(path.join(destDir, "junk.txt"), "nothing useful");
    };
    const outcome = await runCompiledScan({
      workDir,
      fileList: ["App.ipa"],
      scanType: "FULL",
      config: config(),
      runner: noRunner,
      unzip,
      log: silentLog,
    });
    expect(outcome.files).toHaveLength(0);
    expect(outcome.summary.decompiled).toBe(0);
    expect(outcome.summary.failed).toBe(1);
  });
});
