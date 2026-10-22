import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { extractAsciiStrings, findDotApp, extractIpaMetadata } from "./ipa-extract";

let root: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "ipa-test-"));
});
afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

function mkApp(name = "MyApp.app"): string {
  const app = path.join(root, "Payload", name);
  fs.mkdirSync(app, { recursive: true });
  return app;
}

describe("extractAsciiStrings", () => {
  it("pulls printable runs, deduped, skips short ones", () => {
    const buf = Buffer.from("https://api.example.com\x00\x01ab\x00SECRETKEY123\x00https://api.example.com");
    const out = extractAsciiStrings(buf, 4);
    expect(out).toContain("https://api.example.com");
    expect(out).toContain("SECRETKEY123");
    expect(out).not.toContain("ab"); // shorter than minLen
    expect(out.filter((s) => s === "https://api.example.com")).toHaveLength(1); // deduped
  });
});

describe("findDotApp", () => {
  it("finds the .app under Payload", () => {
    const app = mkApp();
    expect(findDotApp(root)).toBe(app);
  });
  it("returns null when there is no .app", () => {
    expect(findDotApp(root)).toBeNull();
  });
});

describe("extractIpaMetadata", () => {
  it("returns empty when no .app is present", () => {
    const out = extractIpaMetadata(root, path.join(root, "out"));
    expect(out).toEqual({ appName: null, written: [] });
  });

  it("writes Info.plist (anchor), strings, frameworks and executable strings", () => {
    const app = mkApp("MyApp.app");
    // binary-plist-like Info.plist with readable keys
    fs.writeFileSync(
      path.join(app, "Info.plist"),
      Buffer.from("bplist00\x00NSAllowsArbitraryLoads\x00CFBundleURLSchemes\x00myapp"),
    );
    fs.mkdirSync(path.join(app, "Frameworks"));
    fs.writeFileSync(path.join(app, "Frameworks", "Alamofire.framework"), "");
    // the main executable (same name as the bundle, no extension)
    fs.writeFileSync(path.join(app, "MyApp"), Buffer.from("https://secret.internal/api\x00token_abc12345"));

    const outDir = path.join(root, "out");
    const res = extractIpaMetadata(root, outDir);

    expect(res.appName).toBe("MyApp.app");
    expect(res.written).toContain("Info.plist");
    expect(res.written).toContain("Info.plist.strings.txt");
    expect(res.written).toContain("frameworks.txt");
    expect(res.written).toContain("executable.strings.txt");

    const info = fs.readFileSync(path.join(outDir, "Info.plist.strings.txt"), "utf8");
    expect(info).toContain("NSAllowsArbitraryLoads");
    expect(info).toContain("CFBundleURLSchemes");

    const fw = fs.readFileSync(path.join(outDir, "frameworks.txt"), "utf8");
    expect(fw).toContain("Alamofire.framework");

    const execStrings = fs.readFileSync(path.join(outDir, "executable.strings.txt"), "utf8");
    expect(execStrings).toContain("https://secret.internal/api");
  });
});
