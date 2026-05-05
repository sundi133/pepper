import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, it } from "node:test";
import AdmZip from "adm-zip";
import { safeExtractZip, SafeExtractError } from "./safe-extract-zip";

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "safe-zip-"));
}

describe("safeExtractZip", () => {
  it("extracts a normal text file", () => {
    const dir = tmpDir();
    const zipPath = path.join(dir, "a.zip");
    const z = new AdmZip();
    z.addFile("src/app.py", Buffer.from("print(1)\n"));
    z.writeZip(zipPath);

    const out = path.join(dir, "out");
    const r = safeExtractZip(zipPath, out, {
      maxFiles: 100,
      maxTotalUncompressedBytes: 1024 * 1024,
      maxSingleFileBytes: 1024 * 1024,
    });
    assert.equal(r.fileCount, 1);
    assert.ok(r.totalBytes > 0);
    const text = fs.readFileSync(path.join(out, "src/app.py"), "utf-8");
    assert.match(text, /print\(1\)/);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  // Note: adm-zip normalizes `../` when building archives; traversal payloads are
  // covered by rejecting `..` path segments when reading raw ZIP entry names.

  it("rejects too many files", () => {
    const dir = tmpDir();
    const zipPath = path.join(dir, "many.zip");
    const z = new AdmZip();
    for (let i = 0; i < 15; i++) {
      z.addFile(`f${i}.txt`, Buffer.from("a"));
    }
    z.writeZip(zipPath);

    const out = path.join(dir, "out");
    assert.throws(
      () =>
        safeExtractZip(zipPath, out, {
          maxFiles: 5,
          maxTotalUncompressedBytes: 1024 * 1024,
          maxSingleFileBytes: 1024,
        }),
      SafeExtractError,
    );
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("rejects oversized entry", () => {
    const dir = tmpDir();
    const zipPath = path.join(dir, "huge.zip");
    const z = new AdmZip();
    z.addFile("big.bin", Buffer.alloc(5000));
    z.writeZip(zipPath);

    const out = path.join(dir, "out");
    assert.throws(
      () =>
        safeExtractZip(zipPath, out, {
          maxFiles: 100,
          maxTotalUncompressedBytes: 1024 * 1024,
          maxSingleFileBytes: 1000,
        }),
      SafeExtractError,
    );
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("skips blocked directories", () => {
    const dir = tmpDir();
    const zipPath = path.join(dir, "blocked.zip");
    const z = new AdmZip();
    z.addFile("node_modules/pkg/index.js", Buffer.from("x"));
    z.addFile("ok.txt", Buffer.from("y"));
    z.writeZip(zipPath);

    const out = path.join(dir, "out");
    const r = safeExtractZip(zipPath, out, {
      maxFiles: 100,
      maxTotalUncompressedBytes: 1024 * 1024,
      maxSingleFileBytes: 1024 * 1024,
    });
    assert.equal(r.fileCount, 1);
    assert.ok(fs.existsSync(path.join(out, "ok.txt")));
    assert.ok(!fs.existsSync(path.join(out, "node_modules")));
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
