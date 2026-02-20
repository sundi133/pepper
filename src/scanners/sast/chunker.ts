import { Chunk } from "../types";
import { MAX_CHUNK_TOKENS, CHUNK_OVERLAP_TOKENS } from "@/lib/constants";

export function chunkFile(
  content: string,
  filePath: string,
  maxTokens = MAX_CHUNK_TOKENS,
  overlapTokens = CHUNK_OVERLAP_TOKENS,
): Chunk[] {
  const lines = content.split("\n");
  if (lines.length === 0) return [];

  const chunks: Chunk[] = [];
  let currentLines: string[] = [];
  let currentTokenEst = 0;
  let startLine = 1;

  for (let i = 0; i < lines.length; i++) {
    const lineTokens = Math.ceil(lines[i].length / 4) + 1;

    if (currentTokenEst + lineTokens > maxTokens && currentLines.length > 0) {
      chunks.push({
        content: addLineNumbers(currentLines, startLine),
        startLine,
        endLine: startLine + currentLines.length - 1,
        filePath,
      });

      const overlapLines = Math.min(
        Math.floor(overlapTokens / 10),
        currentLines.length,
      );
      const backtrack = Math.max(overlapLines, 0);
      startLine = startLine + currentLines.length - backtrack;
      currentLines = currentLines.slice(-backtrack);
      currentTokenEst = currentLines.reduce(
        (sum, l) => sum + Math.ceil(l.length / 4) + 1,
        0,
      );
    }

    currentLines.push(lines[i]);
    currentTokenEst += lineTokens;
  }

  if (currentLines.length > 0) {
    chunks.push({
      content: addLineNumbers(currentLines, startLine),
      startLine,
      endLine: startLine + currentLines.length - 1,
      filePath,
    });
  }

  return chunks;
}

function addLineNumbers(lines: string[], startLine: number): string {
  return lines.map((line, i) => `${startLine + i}: ${line}`).join("\n");
}
