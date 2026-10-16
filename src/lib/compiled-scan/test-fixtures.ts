/**
 * Byte-level fixtures for the compiled-scan tests: minimal but well-formed
 * PE, ZIP, DEX and class files, so no real decompiler or toolchain is needed.
 */

/** A PE image: .NET when `clr` is set (CLI header data directory present), native otherwise. */
export function peFile(opts: { clr: boolean; pe32Plus?: boolean; dirCount?: number }): Buffer {
  const buf = Buffer.alloc(512);
  buf.write("MZ", 0, "latin1");
  const peOffset = 0x80;
  buf.writeUInt32LE(peOffset, 0x3c);
  buf.write("PE\0\0", peOffset, "latin1");
  const optional = peOffset + 24;
  const plus = opts.pe32Plus ?? false;
  buf.writeUInt16LE(plus ? 240 : 224, peOffset + 20); // SizeOfOptionalHeader
  buf.writeUInt16LE(plus ? 0x20b : 0x10b, optional);
  const countOffset = optional + (plus ? 108 : 92);
  buf.writeUInt32LE(opts.dirCount ?? 16, countOffset);
  if (opts.clr) {
    const clr = countOffset + 4 + 14 * 8;
    buf.writeUInt32LE(0x2008, clr); // RVA
    buf.writeUInt32LE(0x48, clr + 4); // size
  }
  return buf;
}

/** A stored (uncompressed) ZIP with the given entries. CRCs are not checked by the reader. */
export function zipFile(entries: Record<string, string | Buffer>): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [name, content] of Object.entries(entries)) {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const nameBuf = Buffer.from(name, "utf8");
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(local, nameBuf, data);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuf);
    offset += 30 + nameBuf.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(Object.keys(entries).length, 8);
  eocd.writeUInt16LE(Object.keys(entries).length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

export function dexFile(): Buffer {
  return Buffer.concat([Buffer.from("dex\n035\0", "latin1"), Buffer.alloc(104)]);
}

/** A class file defining `className` (internal form, e.g. "com/example/Login"). */
export function classFile(className: string): Buffer {
  const parts: Buffer[] = [];
  const u1 = (n: number) => Buffer.from([n]);
  const u2 = (n: number) => {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(n);
    return b;
  };
  const utf8 = (s: string) => Buffer.concat([u1(1), u2(Buffer.byteLength(s)), Buffer.from(s)]);
  parts.push(Buffer.from([0xca, 0xfe, 0xba, 0xbe]), u2(0), u2(61));
  // #1 Long (takes slots 1-2), #3 Utf8 name, #4 Class #3, #5 Utf8 super, #6 Class #5, #7 String #3
  parts.push(u2(8));
  parts.push(Buffer.concat([u1(5), Buffer.alloc(8)]));
  parts.push(utf8(className), Buffer.concat([u1(7), u2(3)]));
  parts.push(utf8("java/lang/Object"), Buffer.concat([u1(7), u2(5)]));
  parts.push(Buffer.concat([u1(8), u2(3)]));
  parts.push(u2(0x21), u2(4), u2(6), u2(0), u2(0), u2(0), u2(0));
  return Buffer.concat(parts);
}
