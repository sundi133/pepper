/**
 * Just enough binary-format parsing to decide what a compiled artifact is
 * before any decompiler runs: whether a .dll/.exe is a .NET assembly or native
 * code, what a ZIP-based archive (JAR/WAR/EAR/APK/AAB) holds and how large it
 * unpacks, and which class a loose .class file defines.
 */
import * as fs from "node:fs";

// ─── PE (Windows .dll / .exe) ─────────────────────────────────────────

export type PeKind = "dotnet" | "native" | "not-pe";

/** Index of the CLI (COM descriptor) header in the optional header's data directories. */
const CLR_DIRECTORY_INDEX = 14;

/**
 * A PE file is a .NET assembly when its CLI header data directory is present
 * (non-zero RVA and size). Everything else that parses as PE is native code,
 * which cannot be turned back into source.
 */
export function detectPeKind(buf: Buffer): PeKind {
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) return "not-pe"; // "MZ"
  const peOffset = buf.readUInt32LE(0x3c);
  if (peOffset + 24 > buf.length) return "not-pe";
  if (buf.readUInt32LE(peOffset) !== 0x00004550) return "not-pe"; // "PE\0\0"

  const optionalHeader = peOffset + 24;
  const optionalSize = buf.readUInt16LE(peOffset + 20);
  if (optionalSize === 0 || optionalHeader + 2 > buf.length) return "native";
  const magic = buf.readUInt16LE(optionalHeader);
  let countOffset: number;
  if (magic === 0x10b) countOffset = optionalHeader + 92; // PE32
  else if (magic === 0x20b) countOffset = optionalHeader + 108; // PE32+
  else return "native";
  if (countOffset + 4 > buf.length) return "native";

  const dirCount = buf.readUInt32LE(countOffset);
  if (dirCount <= CLR_DIRECTORY_INDEX) return "native";
  const clrEntry = countOffset + 4 + CLR_DIRECTORY_INDEX * 8;
  if (clrEntry + 8 > buf.length) return "native";
  const rva = buf.readUInt32LE(clrEntry);
  const size = buf.readUInt32LE(clrEntry + 4);
  return rva !== 0 && size !== 0 ? "dotnet" : "native";
}

/** First `bytes` of a file (fewer when the file is shorter). */
export function readHead(filePath: string, bytes = 64 * 1024): Buffer {
  const fd = fs.openSync(filePath, "r");
  try {
    const buf = Buffer.alloc(bytes);
    const n = fs.readSync(fd, buf, 0, bytes, 0);
    return buf.subarray(0, n);
  } finally {
    fs.closeSync(fd);
  }
}

export function detectPeFile(filePath: string): PeKind {
  try {
    return detectPeKind(readHead(filePath));
  } catch {
    return "not-pe";
  }
}

// ─── Magic numbers ────────────────────────────────────────────────────

export function isZipHeader(buf: Buffer): boolean {
  // Local file header, or the end record of an empty archive.
  return buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 3 || buf[2] === 5);
}

export function isDexHeader(buf: Buffer): boolean {
  return buf.length >= 8 && buf.subarray(0, 4).toString("latin1") === "dex\n";
}

export function isClassHeader(buf: Buffer): boolean {
  return buf.length >= 10 && buf.readUInt32BE(0) === 0xcafebabe;
}

// ─── ZIP central directory ────────────────────────────────────────────

export interface ZipEntry {
  name: string;
  uncompressedSize: number;
}

export interface ZipListing {
  entries: ZipEntry[];
  totalUncompressed: number;
}

const EOCD_SIG = 0x06054b50;
const ZIP64_LOCATOR_SIG = 0x07064b50;
const ZIP64_EOCD_SIG = 0x06064b50;
const CENTRAL_SIG = 0x02014b50;

function readAt(fd: number, position: number, length: number): Buffer {
  const buf = Buffer.alloc(length);
  const n = fs.readSync(fd, buf, 0, length, position);
  return buf.subarray(0, n);
}

/**
 * List a ZIP archive's entries from its central directory without extracting
 * anything. Returns null when the file is not a readable ZIP.
 */
export function listZipEntries(filePath: string, maxEntries = 200_000): ZipListing | null {
  let fd: number;
  try {
    fd = fs.openSync(filePath, "r");
  } catch {
    return null;
  }
  try {
    const size = fs.fstatSync(fd).size;
    if (size < 22) return null;
    const tailLen = Math.min(size, 22 + 0xffff);
    const tail = readAt(fd, size - tailLen, tailLen);
    let eocd = -1;
    for (let i = tail.length - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === EOCD_SIG) {
        eocd = i;
        break;
      }
    }
    if (eocd < 0) return null;

    let count = tail.readUInt16LE(eocd + 10);
    let cdSize = tail.readUInt32LE(eocd + 12);
    let cdOffset = tail.readUInt32LE(eocd + 16);

    if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) {
      const loc = eocd - 20;
      if (loc < 0 || tail.readUInt32LE(loc) !== ZIP64_LOCATOR_SIG) return null;
      const z64Offset = Number(tail.readBigUInt64LE(loc + 8));
      const z64 = readAt(fd, z64Offset, 56);
      if (z64.length < 56 || z64.readUInt32LE(0) !== ZIP64_EOCD_SIG) return null;
      count = Number(z64.readBigUInt64LE(32));
      cdSize = Number(z64.readBigUInt64LE(40));
      cdOffset = Number(z64.readBigUInt64LE(48));
    }
    if (count > maxEntries || cdOffset + cdSize > size) return null;

    const cd = readAt(fd, cdOffset, cdSize);
    const entries: ZipEntry[] = [];
    let total = 0;
    let p = 0;
    for (let i = 0; i < count; i++) {
      if (p + 46 > cd.length || cd.readUInt32LE(p) !== CENTRAL_SIG) return null;
      let uncompressed = cd.readUInt32LE(p + 24);
      const nameLen = cd.readUInt16LE(p + 28);
      const extraLen = cd.readUInt16LE(p + 30);
      const commentLen = cd.readUInt16LE(p + 32);
      const name = cd.subarray(p + 46, p + 46 + nameLen).toString("utf8");
      if (uncompressed === 0xffffffff) {
        // Zip64 extended information: the first field is the uncompressed size.
        const extra = cd.subarray(p + 46 + nameLen, p + 46 + nameLen + extraLen);
        for (let e = 0; e + 4 <= extra.length; ) {
          const id = extra.readUInt16LE(e);
          const len = extra.readUInt16LE(e + 2);
          if (id === 0x0001 && len >= 8) {
            uncompressed = Number(extra.readBigUInt64LE(e + 4));
            break;
          }
          e += 4 + len;
        }
      }
      entries.push({ name, uncompressedSize: uncompressed });
      total += uncompressed;
      p += 46 + nameLen + extraLen + commentLen;
    }
    return { entries, totalUncompressed: total };
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

// ─── Java class files ─────────────────────────────────────────────────

/**
 * Internal name ("com/example/Login$Inner") of the class a .class file
 * defines, read from its constant pool. Null when the bytes are not a class.
 */
export function readClassName(buf: Buffer): string | null {
  if (!isClassHeader(buf)) return null;
  try {
    const count = buf.readUInt16BE(8);
    const utf8 = new Map<number, string>();
    const classRefs = new Map<number, number>();
    let p = 10;
    for (let i = 1; i < count; i++) {
      const tag = buf[p];
      switch (tag) {
        case 1: {
          const len = buf.readUInt16BE(p + 1);
          utf8.set(i, buf.subarray(p + 3, p + 3 + len).toString("utf8"));
          p += 3 + len;
          break;
        }
        case 7: // Class
          classRefs.set(i, buf.readUInt16BE(p + 1));
          p += 3;
          break;
        case 8: // String
        case 16: // MethodType
        case 19: // Module
        case 20: // Package
          p += 3;
          break;
        case 15: // MethodHandle
          p += 4;
          break;
        case 3: // Integer
        case 4: // Float
        case 9: // Fieldref
        case 10: // Methodref
        case 11: // InterfaceMethodref
        case 12: // NameAndType
        case 17: // Dynamic
        case 18: // InvokeDynamic
          p += 5;
          break;
        case 5: // Long
        case 6: // Double
          p += 9;
          i++; // takes two constant pool slots
          break;
        default:
          return null;
      }
      if (p > buf.length) return null;
    }
    const thisClass = buf.readUInt16BE(p + 2);
    const nameIndex = classRefs.get(thisClass);
    const name = nameIndex !== undefined ? utf8.get(nameIndex) : undefined;
    return name && /^[^\s;[]+$/.test(name) ? name : null;
  } catch {
    return null;
  }
}
