import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  detectPeFile,
  detectPeKind,
  isClassHeader,
  isDexHeader,
  isZipHeader,
  listZipEntries,
  readClassName,
} from "./binary-format";
import { classFile, dexFile, peFile, zipFile } from "./test-fixtures";

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-binfmt-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

describe("detectPeKind (native vs .NET)", () => {
  it("recognises a .NET assembly by its CLI header (PE32 and PE32+)", () => {
    expect(detectPeKind(peFile({ clr: true }))).toBe("dotnet");
    expect(detectPeKind(peFile({ clr: true, pe32Plus: true }))).toBe("dotnet");
  });

  it("reports native code when the CLI header is absent", () => {
    expect(detectPeKind(peFile({ clr: false }))).toBe("native");
    expect(detectPeKind(peFile({ clr: false, pe32Plus: true }))).toBe("native");
    // Too few data directories to hold a CLI header.
    expect(detectPeKind(peFile({ clr: true, dirCount: 10 }))).toBe("native");
  });

  it("rejects files that are not PE images", () => {
    expect(detectPeKind(Buffer.from("not a binary at all, just text"))).toBe("not-pe");
    expect(detectPeKind(Buffer.from("\x7fELF" + "\0".repeat(100), "latin1"))).toBe("not-pe");
    const mzOnly = Buffer.alloc(128);
    mzOnly.write("MZ", 0, "latin1");
    mzOnly.writeUInt32LE(0x1000, 0x3c); // PE header beyond the buffer
    expect(detectPeKind(mzOnly)).toBe("not-pe");
  });

  it("reads the header from disk", () => {
    const p = path.join(dir, "App.dll");
    fs.writeFileSync(p, peFile({ clr: true }));
    expect(detectPeFile(p)).toBe("dotnet");
    expect(detectPeFile(path.join(dir, "missing.dll"))).toBe("not-pe");
  });
});

describe("magic numbers", () => {
  it("identifies ZIP, DEX and class files", () => {
    expect(isZipHeader(zipFile({ "a.txt": "x" }))).toBe(true);
    expect(isZipHeader(Buffer.from("MZ......"))).toBe(false);
    expect(isDexHeader(dexFile())).toBe(true);
    expect(isDexHeader(zipFile({}))).toBe(false);
    expect(isClassHeader(classFile("A"))).toBe(true);
    expect(isClassHeader(dexFile())).toBe(false);
  });
});

describe("listZipEntries", () => {
  it("lists entries and the total uncompressed size from the central directory", () => {
    const p = path.join(dir, "app.war");
    fs.writeFileSync(
      p,
      zipFile({
        "WEB-INF/classes/com/x/A.class": Buffer.alloc(100),
        "WEB-INF/lib/dep.jar": Buffer.alloc(50),
        "index.jsp": "<html/>",
      }),
    );
    const listing = listZipEntries(p);
    expect(listing?.entries.map((e) => e.name)).toEqual([
      "WEB-INF/classes/com/x/A.class",
      "WEB-INF/lib/dep.jar",
      "index.jsp",
    ]);
    expect(listing?.totalUncompressed).toBe(157);
  });

  it("returns null for a file that is not a ZIP", () => {
    const p = path.join(dir, "fake.jar");
    fs.writeFileSync(p, "this is not a zip archive, only text pretending to be one");
    expect(listZipEntries(p)).toBeNull();
    expect(listZipEntries(path.join(dir, "missing.jar"))).toBeNull();
  });
});

describe("readClassName", () => {
  it("reads the defined class from the constant pool (including two-slot constants)", () => {
    expect(readClassName(classFile("com/example/Login"))).toBe("com/example/Login");
    expect(readClassName(classFile("com/example/Login$Inner"))).toBe("com/example/Login$Inner");
  });

  it("returns null for truncated or foreign bytes", () => {
    expect(readClassName(classFile("com/example/Login").subarray(0, 20))).toBeNull();
    expect(readClassName(dexFile())).toBeNull();
  });
});
