import { describe, expect, it, vi } from "vitest";

// Record which files each scanner was given.
const { seen, recorder } = vi.hoisted(() => {
  const seen: Record<string, string[]> = {};
  const recorder = (name: string) => ({
    name,
    scan: async (ctx: { fileList: string[] }) => {
      seen[name] = [...ctx.fileList];
      return [];
    },
  });
  return { seen, recorder };
});

vi.mock("./secrets", () => ({
  secretsPatternScanner: recorder("SECRETS_PATTERN"),
  secretsLlmScanner: recorder("SECRETS_LLM"),
}));
vi.mock("./sca", () => ({
  scaScanner: recorder("SCA"),
  parseDependencies: () => ({ dependencies: [] }),
}));
vi.mock("./sca/malicious-pkg", () => ({ maliciousPkgScanner: recorder("MALICIOUS_PKG") }));

import { runScanners } from "./index";

const ctx = (scanType: string, decompiledFileList?: string[]) =>
  ({
    workDir: "/nonexistent",
    fileList: ["src/a.ts", "pom.xml"],
    decompiledFileList,
    scanType,
    orgSettings: { enableLlmSast: false, enableLlmSecrets: false, vulnDbMode: "offline", osvApiUrl: "" },
  }) as never;

describe("runScanners with decompiled compiled code", () => {
  it("gives decompiled source to the secrets scanner", async () => {
    const result = await runScanners(ctx("SECRETS_ONLY", ["__decompiled__/1-app.jar/com/x/A.java"]));
    expect(seen.SECRETS_PATTERN).toEqual(["src/a.ts", "pom.xml", "__decompiled__/1-app.jar/com/x/A.java"]);
    expect(result.filesScanned).toBe(3);
  });

  it("keeps decompiled files away from dependency scanners", async () => {
    await runScanners(ctx("SCA_ONLY", ["__decompiled__/1-app.jar/META-INF/x/pom.xml"]));
    expect(seen.SCA).toEqual(["src/a.ts", "pom.xml"]);
    expect(seen.MALICIOUS_PKG).toEqual(["src/a.ts", "pom.xml"]);
  });

  it("changes nothing when there is no decompiled code", async () => {
    const result = await runScanners(ctx("SECRETS_ONLY"));
    expect(seen.SECRETS_PATTERN).toEqual(["src/a.ts", "pom.xml"]);
    expect(result.filesScanned).toBe(2);
  });
});
