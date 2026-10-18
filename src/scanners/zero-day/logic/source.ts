/**
 * Source access for the logic passes: read files once, number their lines for
 * the model, and check that a line the model cites really says what it quoted.
 */
import * as fs from "fs";
import * as path from "path";
import { LLM_MAX_FILE_SIZE_BYTES } from "@/lib/constants";

export class SourceFiles {
  private cache = new Map<string, string[] | null>();
  constructor(private workDir: string) {}

  /** Lines of a file (1-based access via line()), or null when unreadable. */
  lines(file: string): string[] | null {
    if (!this.cache.has(file)) {
      let lines: string[] | null = null;
      try {
        const full = path.join(this.workDir, file);
        if (fs.statSync(full).size <= LLM_MAX_FILE_SIZE_BYTES) {
          lines = fs.readFileSync(full, "utf8").split("\n");
        }
      } catch {
        lines = null;
      }
      this.cache.set(file, lines);
    }
    return this.cache.get(file) ?? null;
  }

  line(file: string, n: number): string | undefined {
    const lines = this.lines(file);
    return lines && n >= 1 && n <= lines.length ? lines[n - 1] : undefined;
  }

  /** Lines [start, end] prefixed with their numbers, as the model sees code. */
  numbered(file: string, start = 1, end = Number.MAX_SAFE_INTEGER): string {
    const lines = this.lines(file) ?? [];
    const from = Math.max(1, start);
    const to = Math.min(lines.length, end);
    const out: string[] = [];
    for (let i = from; i <= to; i++) out.push(`${i}: ${lines[i - 1]}`);
    return out.join("\n");
  }
}

const squash = (s: string) => s.replace(/\s+/g, "").toLowerCase();

/**
 * Whether `quote` appears on `line` of `file`, or within `slack` lines of it
 * (models are often off by one or two). Whitespace and case are ignored. A
 * quote must carry at least 3 non-space characters to count as evidence.
 */
export function verifyQuote(src: SourceFiles, file: string, line: number, quote: unknown, slack = 2): boolean {
  if (typeof quote !== "string" || !Number.isInteger(line)) return false;
  const q = squash(quote).replace(/^\d+:/, "");
  if (q.length < 3) return false;
  for (let n = line - slack; n <= line + slack; n++) {
    const text = src.line(file, n);
    if (text !== undefined && squash(text).includes(q)) return true;
  }
  // A quote spanning two lines.
  for (let n = line - slack; n <= line + slack; n++) {
    const a = src.line(file, n);
    const b = src.line(file, n + 1);
    if (a !== undefined && b !== undefined && squash(a + b).includes(q)) return true;
  }
  return false;
}

/** Map a path the model wrote onto one of `known` (exact, or a unique suffix). */
export function resolveKnownFile(raw: unknown, known: Iterable<string>): string | undefined {
  if (typeof raw !== "string" || !raw.trim()) return undefined;
  const norm = (p: string) => p.trim().replace(/\\/g, "/").replace(/^(?:\.\/|\/)+/, "");
  const want = norm(raw);
  const all = [...known];
  const exact = all.find((s) => norm(s) === want);
  if (exact) return exact;
  const matches = all.filter((s) => norm(s).endsWith(`/${want}`) || want.endsWith(`/${norm(s)}`));
  return matches.length === 1 ? matches[0] : undefined;
}

/** Run `fn` over `items` with at most `limit` in flight; results keep input order. */
export async function mapPool<T, R>(items: T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}
