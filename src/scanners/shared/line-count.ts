import * as fs from "node:fs/promises";
import * as path from "node:path";

/** Bytes inspected for a NUL byte to decide a file is binary (git uses the same heuristic). */
const BINARY_SNIFF_BYTES = 8000;
const CONCURRENCY = 64;

/**
 * Lines in a text buffer: every newline, plus a final line without one.
 * Blank lines count, so the total matches `wc -l` (+1 for a missing final newline).
 * Binary buffers count as 0.
 */
export function countBufferLines(buf: Buffer): number {
  if (buf.length === 0) return 0;
  if (buf.subarray(0, BINARY_SNIFF_BYTES).includes(0)) return 0;
  let lines = 0;
  for (let i = buf.indexOf(10); i !== -1; i = buf.indexOf(10, i + 1)) lines++;
  return buf[buf.length - 1] === 10 ? lines : lines + 1;
}

/** Total lines across the given files (relative to workDir). Unreadable files count as 0. */
export async function countLines(workDir: string, files: Iterable<string>): Promise<number> {
  const list = [...files];
  let total = 0;
  for (let i = 0; i < list.length; i += CONCURRENCY) {
    const counts = await Promise.all(
      list.slice(i, i + CONCURRENCY).map(async (f) => {
        try {
          return countBufferLines(await fs.readFile(path.join(workDir, f)));
        } catch {
          return 0;
        }
      }),
    );
    for (const c of counts) total += c;
  }
  return total;
}
