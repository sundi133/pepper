import { execFileSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { extractArchive } from "./extract-archive";

describe("extractArchive", () => {
  it("throws when destination directory does not exist", () => {
    expect(() =>
      extractArchive("/nonexistent/source.zip", "/nonexistent/dest"),
    ).toThrow(/destination does not exist/);
  });

  it("throws for unsupported archive extension", () => {
    const tmp = os.tmpdir();
    expect(() =>
      extractArchive(path.join(tmp, "pepper-test-fake.unknown"), tmp),
    ).toThrow(/Unsupported archive format/);
  });
});

// ─── ZIP files through the real unzip ─────────────────────────────────

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(data: Buffer): number {
  let c = 0xffffffff;
  for (const byte of data) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * A stored (uncompressed) ZIP. `madeOnWindows` marks it as created on
 * MS-DOS/Windows, as Windows PowerShell's Compress-Archive does, which is when
 * unzip converts backslashes in names to directories.
 */
function buildZip(entries: Array<{ name: string; data: string }>, madeOnWindows = false): Buffer {
  const local: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name, "utf8");
    const data = Buffer.from(entry.data, "utf8");
    const crc = crc32(data);

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4); // version needed
    lh.writeUInt16LE(0x21, 12); // date: 1980-01-01
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(data.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(name.length, 26);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(madeOnWindows ? 20 : (3 << 8) | 20, 4); // version made by: MS-DOS or Unix
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x21, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(data.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    // External attributes: Unix zips carry the file mode (rw-r--r--) in the high 16 bits.
    if (!madeOnWindows) ch.writeUInt32LE((0o100644 << 16) >>> 0, 38);
    ch.writeUInt32LE(offset, 42);

    local.push(lh, name, data);
    central.push(ch, name);
    offset += lh.length + name.length + data.length;
  }
  const cd = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, cd, eocd]);
}

function unzipPath(): string | null {
  try {
    return execFileSync("sh", ["-c", "command -v unzip"], { encoding: "utf8" }).trim() || null;
  } catch {
    return null;
  }
}

const UNZIP = process.platform === "win32" ? null : unzipPath();

// Runs like the Alpine worker: the real unzip, and BusyBox tar, which cannot
// read ZIP files (macOS's bsdtar can, which would hide unzip failures here).
describe.skipIf(!UNZIP)("extractArchive ZIP files", () => {
  let workDir: string;
  let binDir: string;
  let savedPath: string | undefined;
  beforeEach(() => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-zip-"));
    binDir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-zip-bin-"));
    fs.symlinkSync(UNZIP!, path.join(binDir, "unzip"));
    fs.writeFileSync(path.join(binDir, "tar"), '#!/bin/sh\necho "tar: invalid tar magic" >&2\nexit 1\n', { mode: 0o755 });
    savedPath = process.env.PATH;
    process.env.PATH = binDir;
  });
  afterEach(() => {
    process.env.PATH = savedPath;
    fs.rmSync(workDir, { recursive: true, force: true });
    fs.rmSync(binDir, { recursive: true, force: true });
  });

  /** Like the worker: the archive is written into the folder it is extracted into. */
  function extract(zip: Buffer): void {
    const archivePath = path.join(workDir, "source.zip");
    fs.writeFileSync(archivePath, zip);
    extractArchive(archivePath, workDir);
  }

  it("extracts an ordinary zip", () => {
    extract(buildZip([{ name: "src/app.py", data: "print(1)\n" }]));
    expect(fs.readFileSync(path.join(workDir, "src", "app.py"), "utf8")).toBe("print(1)\n");
  });

  it("extracts a zip made by Windows PowerShell (backslash separators, unzip exit 1)", () => {
    extract(
      buildZip(
        [
          { name: "src\\app.py", data: "import os\n" },
          { name: "src\\config\\settings.json", data: "{}" },
        ],
        true,
      ),
    );
    expect(fs.readFileSync(path.join(workDir, "src", "app.py"), "utf8")).toBe("import os\n");
    expect(fs.existsSync(path.join(workDir, "src", "config", "settings.json"))).toBe(true);
  });

  it("keeps entries with ../ inside the destination", () => {
    extract(buildZip([{ name: "../escape.txt", data: "x" }, { name: "ok.txt", data: "y" }]));
    expect(fs.existsSync(path.join(workDir, "..", "escape.txt"))).toBe(false);
    expect(fs.existsSync(path.join(workDir, "ok.txt"))).toBe(true);
  });

  it("reports unzip's own reason for a damaged zip, not only tar's", () => {
    const zip = buildZip([{ name: "a.txt", data: "hello world".repeat(100) }]);
    let message = "";
    try {
      extract(zip.subarray(0, Math.floor(zip.length / 2)));
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toMatch(/^Failed to extract ZIP \(tried unzip, tar\): unzip: /);
    expect(message).toMatch(/central directory|zipfile/i);
    expect(message).toContain(" | tar: tar: invalid tar magic");
  });
});
