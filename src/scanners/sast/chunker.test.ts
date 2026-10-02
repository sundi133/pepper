import { describe, it, expect } from "vitest";
import { chunkFile, wholeFileChunk, estimateTokens } from "./chunker";

describe("estimateTokens", () => {
  it("approximates four characters per token", () => {
    expect(estimateTokens("12345678")).toBe(2);
  });
});

describe("wholeFileChunk", () => {
  const content = ["line one", "line two", "line three"].join("\n");

  it("returns a single line-numbered chunk covering the whole file", () => {
    const chunk = wholeFileChunk(content, "src/a.ts", 1000);
    expect(chunk).not.toBeNull();
    expect(chunk!.wholeFile).toBe(true);
    expect(chunk!.startLine).toBe(1);
    expect(chunk!.endLine).toBe(3);
    expect(chunk!.content).toContain("1: line one");
    expect(chunk!.content).toContain("3: line three");
  });

  it("returns null when the file exceeds the budget", () => {
    expect(wholeFileChunk(content, "src/a.ts", 1)).toBeNull();
  });

  it("returns null for empty/whitespace content", () => {
    expect(wholeFileChunk("   \n  ", "src/a.ts", 1000)).toBeNull();
  });
});

describe("chunkFile", () => {
  it("covers all lines across chunks with overlap", () => {
    const lines = Array.from({ length: 200 }, (_, i) => `const v${i} = ${i};`);
    const chunks = chunkFile(lines.join("\n"), "src/big.ts", 100, 20);
    expect(chunks.length).toBeGreaterThan(1);
    expect(chunks[0].startLine).toBe(1);
    expect(chunks[chunks.length - 1].endLine).toBe(200);
  });
});
