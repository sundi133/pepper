/**
 * Best-effort syntax validation for files the remediation agent changed.
 *
 * Checks are regression-only: a file fails only when the ORIGINAL parsed and
 * the fixed version does not. Files that already failed to parse (templates,
 * JSONC, partial snippets) are reported as skipped instead of blamed on the fix.
 */
import { execFile } from "child_process";
import * as path from "path";

export type CheckStatus = "passed" | "failed" | "skipped";

export interface SyntaxCheckResult {
  status: CheckStatus;
  detail: string;
}

type Parser = (content: string, filePath: string) => Promise<string | null>;

const ESBUILD_LOADERS: Record<string, string> = {
  ".js": "js",
  ".mjs": "js",
  ".cjs": "js",
  ".jsx": "jsx",
  ".ts": "ts",
  ".mts": "ts",
  ".cts": "ts",
  ".tsx": "tsx",
};

type EsbuildModule = {
  transform: (
    code: string,
    options: { loader: string; logLevel?: string },
  ) => Promise<unknown>;
};

let esbuildPromise: Promise<EsbuildModule | null> | null = null;

/**
 * esbuild ships with tsx (a runtime dependency), so it is present in the
 * worker image; still loaded lazily and optional so a missing binary only
 * downgrades JS/TS checks to "skipped".
 */
function loadEsbuild(): Promise<EsbuildModule | null> {
  if (!esbuildPromise) {
    esbuildPromise = import("esbuild")
      .then((m) => (m as unknown as { default?: EsbuildModule }).default ?? (m as unknown as EsbuildModule))
      .catch(() => null);
  }
  return esbuildPromise;
}

function firstLine(message: string): string {
  return message.split("\n").find((l) => l.trim())?.trim().slice(0, 300) ?? message;
}

const parseJsTs: Parser = async (content, filePath) => {
  const esbuild = await loadEsbuild();
  if (!esbuild) throw new Error("esbuild unavailable");
  const loader = ESBUILD_LOADERS[path.extname(filePath).toLowerCase()];
  try {
    await esbuild.transform(content, { loader, logLevel: "silent" });
    return null;
  } catch (e) {
    const errors = (e as { errors?: Array<{ text: string; location?: { line: number } }> }).errors;
    if (errors?.length) {
      const first = errors[0];
      return `${first.location ? `line ${first.location.line}: ` : ""}${first.text}`;
    }
    return firstLine(e instanceof Error ? e.message : String(e));
  }
};

const parseJson: Parser = async (content) => {
  try {
    JSON.parse(content);
    return null;
  } catch (e) {
    return firstLine(e instanceof Error ? e.message : String(e));
  }
};

function runWithStdin(
  cmd: string,
  args: string[],
  input: string,
): Promise<{ code: number; stderr: string; missing: boolean }> {
  return new Promise((resolve) => {
    const child = execFile(
      cmd,
      args,
      { timeout: 20_000, maxBuffer: 1024 * 1024 },
      (err, _stdout, stderr) => {
        if (!err) return resolve({ code: 0, stderr: "", missing: false });
        resolve({
          code: 1,
          stderr: String(stderr || err.message),
          missing: (err as NodeJS.ErrnoException).code === "ENOENT",
        });
      },
    );
    child.stdin?.on("error", () => {
      /* process exited early (e.g. ENOENT) */
    });
    child.stdin?.end(input);
  });
}

const parsePython: Parser = async (content) => {
  const r = await runWithStdin(
    "python3",
    ["-c", "import ast,sys; ast.parse(sys.stdin.read())"],
    content,
  );
  if (r.missing) throw new Error("python3 unavailable");
  if (r.code === 0) return null;
  const lines = r.stderr.trim().split("\n");
  return lines[lines.length - 1]?.slice(0, 300) || "Python syntax error";
};

const parseGo: Parser = async (content) => {
  const r = await runWithStdin("gofmt", ["-e"], content);
  if (r.missing) throw new Error("gofmt unavailable");
  if (r.code === 0) return null;
  return firstLine(r.stderr) || "Go syntax error";
};

const parseRuby: Parser = async (content) => {
  const r = await runWithStdin("ruby", ["-c"], content);
  if (r.missing) throw new Error("ruby unavailable");
  if (r.code === 0) return null;
  return firstLine(r.stderr) || "Ruby syntax error";
};

const parsePhp: Parser = async (content) => {
  const r = await runWithStdin("php", ["-l"], content);
  if (r.missing) throw new Error("php unavailable");
  if (r.code === 0) return null;
  return firstLine(r.stderr) || "PHP syntax error";
};

function parserFor(filePath: string): { name: string; parse: Parser } | null {
  const ext = path.extname(filePath).toLowerCase();
  if (ESBUILD_LOADERS[ext]) return { name: "JavaScript/TypeScript", parse: parseJsTs };
  if (ext === ".json") return { name: "JSON", parse: parseJson };
  if (ext === ".py") return { name: "Python", parse: parsePython };
  if (ext === ".go") return { name: "Go", parse: parseGo };
  if (ext === ".rb") return { name: "Ruby", parse: parseRuby };
  if (ext === ".php") return { name: "PHP", parse: parsePhp };
  return null;
}

export async function checkSyntax(
  filePath: string,
  before: string | null,
  after: string,
): Promise<SyntaxCheckResult> {
  const parser = parserFor(filePath);
  if (!parser) {
    return { status: "skipped", detail: `No syntax checker for ${path.extname(filePath) || "this file type"}` };
  }
  try {
    const afterErr = await parser.parse(after, filePath);
    if (!afterErr) {
      return { status: "passed", detail: `${parser.name} parses cleanly` };
    }
    if (before !== null) {
      const beforeErr = await parser.parse(before, filePath);
      if (beforeErr) {
        return {
          status: "skipped",
          detail: `Original file did not parse as ${parser.name} either`,
        };
      }
    }
    return { status: "failed", detail: `${parser.name}: ${afterErr}` };
  } catch (e) {
    return {
      status: "skipped",
      detail: e instanceof Error ? e.message : "Syntax checker unavailable",
    };
  }
}
