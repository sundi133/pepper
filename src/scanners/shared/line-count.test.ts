import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { countBufferLines, countLines } from "./line-count";

describe("countBufferLines", () => {
  it("counts every line, including blank ones and a last line without a newline", () => {
    expect(countBufferLines(Buffer.from(""))).toBe(0);
    expect(countBufferLines(Buffer.from("a"))).toBe(1);
    expect(countBufferLines(Buffer.from("a\n"))).toBe(1);
    expect(countBufferLines(Buffer.from("a\n\n\nb"))).toBe(4);
    expect(countBufferLines(Buffer.from("a\r\nb\r\n"))).toBe(2);
  });

  it("does not count binary files", () => {
    expect(countBufferLines(Buffer.from([0x89, 0x50, 0x00, 0x0a, 0x0a]))).toBe(0);
  });
});

describe("countLines", () => {
  it("sums lines across files and ignores missing ones", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lines-"));
    fs.mkdirSync(path.join(dir, "src"));
    fs.writeFileSync(path.join(dir, "src/a.ts"), "1\n2\n3\n");
    fs.writeFileSync(path.join(dir, "b.py"), "x\n\ny");
    expect(await countLines(dir, ["src/a.ts", "b.py", "gone.js"])).toBe(6);
  });
});
