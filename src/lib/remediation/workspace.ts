/**
 * A throwaway git checkout the remediation agent edits, commits in and pushes
 * from. Every git error is scrubbed of the credential-bearing URL before it
 * can reach logs, the database or the UI.
 */
import { execFile } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { safeRepoRelativePath } from "./edits";

const GIT_TIMEOUT_MS = 180_000;
/** Files larger than this are never loaded as agent context. */
export const MAX_CONTEXT_FILE_BYTES = 400_000;

const IGNORED_DIRS = new Set([
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  ".next",
  "target",
  "__pycache__",
  ".venv",
  "venv",
  "coverage",
]);

export class RemediationWorkspace {
  readonly dir: string;
  private readonly authedUrl: string;
  private readonly displayUrl: string;
  baseBranch = "";
  /** Commit the run started from — file contents here match the scan's line numbers. */
  baseSha = "";

  private constructor(dir: string, authedUrl: string, displayUrl: string) {
    this.dir = dir;
    this.authedUrl = authedUrl;
    this.displayUrl = displayUrl;
  }

  private scrub(text: string): string {
    let out = text.split(this.authedUrl).join(this.displayUrl);
    // Belt-and-braces: drop any userinfo git echoes back in other forms.
    out = out.replace(/(https?:\/\/)[^@\s/]+@/gi, "$1");
    return out;
  }

  private git(args: string[], timeout = GIT_TIMEOUT_MS): Promise<string> {
    return new Promise((resolve, reject) => {
      execFile(
        "git",
        args,
        {
          cwd: this.dir,
          timeout,
          maxBuffer: 16 * 1024 * 1024,
          env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
        },
        (err, stdout, stderr) => {
          if (err) {
            const detail = this.scrub(String(stderr || err.message)).trim();
            reject(new Error(detail.split("\n").slice(-3).join(" ").slice(0, 500) || "git failed"));
            return;
          }
          resolve(String(stdout));
        },
      );
    });
  }

  /**
   * Shallow-clone the repository. When `preferredBranch` does not exist the
   * repository's default branch is used instead.
   */
  static async clone(options: {
    authedUrl: string;
    displayUrl: string;
    preferredBranch: string | null;
    runId: string;
  }): Promise<RemediationWorkspace> {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `pepper-remediate-${options.runId}-`));
    const ws = new RemediationWorkspace(dir, options.authedUrl, options.displayUrl);
    const base = ["clone", "--depth", "1", "--no-tags"];
    try {
      if (options.preferredBranch) {
        try {
          await ws.git([...base, "--branch", options.preferredBranch, options.authedUrl, "."]);
        } catch (e) {
          if (!/Remote branch|not found/i.test((e as Error).message)) throw e;
          fs.rmSync(dir, { recursive: true, force: true });
          fs.mkdirSync(dir, { recursive: true });
          await ws.git([...base, options.authedUrl, "."]);
        }
      } else {
        await ws.git([...base, options.authedUrl, "."]);
      }
      ws.baseBranch = (await ws.git(["rev-parse", "--abbrev-ref", "HEAD"])).trim();
      ws.baseSha = (await ws.git(["rev-parse", "HEAD"])).trim();
      return ws;
    } catch (e) {
      ws.dispose();
      throw e;
    }
  }

  /** Repo-relative paths of tracked text-ish files, skipping vendored dirs. */
  listFiles(limit = 20_000): string[] {
    const out: string[] = [];
    const walk = (rel: string) => {
      if (out.length >= limit) return;
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(path.join(this.dir, rel), { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries) {
        if (out.length >= limit) return;
        const child = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) {
          if (!IGNORED_DIRS.has(e.name)) walk(child);
        } else if (e.isFile()) {
          out.push(child);
        }
      }
    };
    walk("");
    return out.sort();
  }

  private abs(relPath: string): string {
    const safe = safeRepoRelativePath(relPath);
    if (!safe) throw new Error(`Unsafe path: ${relPath}`);
    const full = path.resolve(this.dir, safe);
    if (!full.startsWith(path.resolve(this.dir) + path.sep)) {
      throw new Error(`Path escapes repository: ${relPath}`);
    }
    return full;
  }

  exists(relPath: string): boolean {
    try {
      return fs.statSync(this.abs(relPath)).isFile();
    } catch {
      return false;
    }
  }

  /** File contents, or null when missing, binary or too large. */
  read(relPath: string, maxBytes = MAX_CONTEXT_FILE_BYTES): string | null {
    try {
      const full = this.abs(relPath);
      const stat = fs.statSync(full);
      if (!stat.isFile() || stat.size > maxBytes) return null;
      const buf = fs.readFileSync(full);
      if (buf.subarray(0, 8000).includes(0)) return null;
      return buf.toString("utf8");
    } catch {
      return null;
    }
  }

  /** File contents at the base commit (before any fix in this run), or null. */
  async readAtBase(relPath: string): Promise<string | null> {
    const safe = safeRepoRelativePath(relPath);
    if (!safe || !this.baseSha) return null;
    try {
      return await this.git(["show", `${this.baseSha}:${safe}`]);
    } catch {
      return null;
    }
  }

  write(relPath: string, content: string): void {
    const full = this.abs(relPath);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, "utf8");
  }

  remove(relPath: string): void {
    try {
      fs.unlinkSync(this.abs(relPath));
    } catch {
      /* already gone */
    }
  }

  async createBranch(name: string): Promise<void> {
    await this.git(["checkout", "-b", name]);
  }

  /** Stage the given paths and commit; returns the new commit SHA. */
  async commit(paths: string[], message: string): Promise<string> {
    const safe = paths.map((p) => safeRepoRelativePath(p)).filter((p): p is string => !!p);
    await this.git(["add", "--", ...safe]);
    await this.git([
      "-c",
      "user.name=Pepper AI Remediation",
      "-c",
      "user.email=pepper-remediation@users.noreply.local",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "--no-verify",
      "-m",
      message,
    ]);
    return (await this.git(["rev-parse", "HEAD"])).trim();
  }

  async push(branch: string): Promise<void> {
    await this.git(["push", "--no-verify", this.authedUrl, `HEAD:refs/heads/${branch}`]);
  }

  dispose(): void {
    try {
      fs.rmSync(this.dir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}

/**
 * Map a scanner-reported path onto the checkout. Upload scans often carry an
 * archive prefix (`project-main/src/x.ts`) that the repo does not have, so
 * strip leading segments, then fall back to a unique basename match.
 */
export function resolveFindingPath(
  reported: string | null | undefined,
  files: string[],
): string | null {
  const norm = safeRepoRelativePath(reported ?? "");
  if (!norm) return null;
  const set = new Set(files);
  if (set.has(norm)) return norm;
  const parts = norm.split("/");
  for (let i = 1; i < parts.length; i++) {
    const candidate = parts.slice(i).join("/");
    if (set.has(candidate)) return candidate;
  }
  const basename = parts[parts.length - 1];
  const matches = files.filter((f) => f === basename || f.endsWith(`/${basename}`));
  return matches.length === 1 ? matches[0] : null;
}

/** Git-safe branch name for a run. */
export function remediationBranchName(runId: string, now = new Date()): string {
  const stamp = now.toISOString().slice(0, 10).replace(/-/g, "");
  return `pepper/ai-remediation-${stamp}-${runId.slice(-8).toLowerCase().replace(/[^a-z0-9]/g, "")}`;
}
