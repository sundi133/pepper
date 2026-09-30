import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { describe, expect, it, vi } from "vitest";
import type { Dependency } from "../types";

const queried: Dependency[][] = [];
vi.mock("./osv-client", () => ({
  queryOsvBatch: vi.fn(async (deps: Dependency[]) => {
    queried.push(deps);
    return [];
  }),
}));
vi.mock("./deps-dev-client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./deps-dev-client")>()),
  fetchVersionInfoBatch: vi.fn(async () => new Map()),
}));
vi.mock("@/lib/epss-kev-enrichment", () => ({ enrichFindingsWithEpssKev: vi.fn(async (f: unknown) => f) }));

import { scaScanner } from "./index";

describe("SCA ecosystems", () => {
  it("never sends CocoaPods to OSV (it would reject the whole batch) but still scans the rest", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sca-eco-"));
    fs.writeFileSync(path.join(dir, "Podfile.lock"), "PODS:\n  - Alamofire (5.6.4)\n");
    fs.writeFileSync(path.join(dir, "Cartfile.resolved"), 'github "ReactiveX/RxSwift" "6.5.0"\n');
    fs.writeFileSync(path.join(dir, "packages.config"), '<packages><package id="jQuery" version="3.4.1" /></packages>');
    await scaScanner.scan({
      workDir: dir,
      fileList: ["Podfile.lock", "Cartfile.resolved", "packages.config"],
      scanType: "SCA_ONLY",
      orgSettings: { llmProvider: "", llmBaseUrl: "", llmModel: "", enableLlmSast: false, enableLlmSecrets: false, osvApiUrl: "https://osv.test", vulnDbMode: "online" },
    });
    fs.rmSync(dir, { recursive: true });
    const sent = queried.flat().map((d) => `${d.ecosystem}:${d.name}`);
    expect(sent.sort()).toEqual(["NuGet:jQuery", "SwiftURL:github.com/ReactiveX/RxSwift"]);
  });
});
