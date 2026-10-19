/** Git facts about a workspace folder, read with the git CLI. */
import { execFile } from "child_process";
import * as fs from "fs";
import * as path from "path";

function git(cwd: string, args: string[], maxBuffer = 16 * 1024 * 1024): Promise<string | null> {
  return new Promise((resolve) => {
    execFile("git", args, { cwd, timeout: 15_000, maxBuffer, windowsHide: true }, (err, stdout) => resolve(err ? null : stdout));
  });
}

export interface GitInfo { root: string; remote: string | null; branch: string | null }

export async function gitInfo(folder: string): Promise<GitInfo | null> {
  const root = (await git(folder, ["rev-parse", "--show-toplevel"]))?.trim();
  if (!root) return null;
  let remote = (await git(root, ["config", "--get", "remote.origin.url"]))?.trim() || null;
  if (!remote) {
    const first = (await git(root, ["remote"]))?.split("\n").find(Boolean);
    if (first) remote = (await git(root, ["config", "--get", `remote.${first}.url`]))?.trim() || null;
  }
  const branch = (await git(root, ["rev-parse", "--abbrev-ref", "HEAD"]))?.trim() || null;
  let real = path.resolve(root);
  try {
    real = fs.realpathSync.native(real);
  } catch {
    // keep git's path
  }
  return { root: real, remote, branch: branch === "HEAD" ? null : branch };
}

/** Tracked files plus untracked ones that aren't ignored, relative to the root. */
export async function workingTreeFiles(root: string): Promise<string[]> {
  const out = await git(root, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], 256 * 1024 * 1024);
  if (!out) return [];
  return [...new Set(out.split("\0").filter(Boolean))].filter((f) => {
    try {
      return fs.statSync(path.join(root, f)).isFile();
    } catch {
      return false; // deleted but still in the index
    }
  });
}
