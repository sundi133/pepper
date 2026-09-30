#!/usr/bin/env node
/**
 * pepper scan — developer pre-push security scan.
 *
 * Packages the commits you are about to push (tracked files at HEAD), uploads
 * them to your Pepper server for a full cloud scan (SAST-LLM, SCA, secrets, IaC,
 * container, K8s), streams a summary to the terminal, and can download the
 * report / SBOM / VEX. The scan runs as a throwaway "ephemeral" scan, so it
 * never touches your real project's scan on the server.
 *
 * Zero dependencies — Node 18+ (uses global fetch/FormData/Blob).
 *
 * Config (env or ~/.pepper/config as KEY=VALUE lines):
 *   PEPPER_API_URL   e.g. https://pepper.your-org.com  (default http://localhost:3000)
 *   PEPPER_API_KEY   ppr_xxxxxxxx  (Settings → API Keys)
 *
 * Usage:
 *   pepper-scan.mjs [--type full|sca|secrets|...] [--download DIR] [--gate]
 *                   [--wait=false] [--json]
 *
 * Exit codes:
 *   0  scan completed (advisory: gate result reported but does not fail)
 *   1  --gate given and the build gate FAILED
 *   2  configuration or scan error
 */

import { execFileSync } from "node:child_process";
import { readFileSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// ─── Config ──────────────────────────────────────────────────────────────────

function loadConfig() {
  const cfg = {
    url: process.env.PEPPER_API_URL || "http://localhost:3000",
    key: process.env.PEPPER_API_KEY || "",
    scanType: (process.env.PEPPER_SCAN_TYPE || "FULL").toUpperCase(),
  };
  // ~/.pepper/config fills gaps but never overrides an explicit env var.
  const file = join(homedir(), ".pepper", "config");
  if (existsSync(file)) {
    for (const line of readFileSync(file, "utf8").split("\n")) {
      const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.+?)\s*$/);
      if (!m) continue;
      if (m[1] === "PEPPER_API_URL" && !process.env.PEPPER_API_URL) cfg.url = m[2];
      if (m[1] === "PEPPER_API_KEY" && !process.env.PEPPER_API_KEY) cfg.key = m[2];
    }
  }
  cfg.url = cfg.url.replace(/\/+$/, "");
  return cfg;
}

function parseArgs(argv) {
  const opts = {
    command: "scan",
    type: null,
    download: null,
    gate: false,
    wait: true,
    json: false,
    diff: null,
  };
  // A leading bare word (not a flag) is a subcommand, e.g. `install-hook`.
  let start = 0;
  if (argv[0] && !argv[0].startsWith("-")) {
    opts.command = argv[0];
    start = 1;
  }
  for (let i = start; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--type") opts.type = argv[++i]?.toUpperCase();
    else if (a.startsWith("--type=")) opts.type = a.slice(7).toUpperCase();
    else if (a === "--download") opts.download = argv[++i] || "./pepper-report";
    else if (a.startsWith("--download=")) opts.download = a.slice(11);
    else if (a === "--gate") opts.gate = true;
    else if (a === "--wait=false" || a === "--no-wait") opts.wait = false;
    else if (a === "--json") opts.json = true;
    else if (a === "--diff") opts.diff = argv[++i] || "@{upstream}";
    else if (a.startsWith("--diff=")) opts.diff = a.slice(7);
  }
  return opts;
}

/** package.json script hooks that identify a dependency manifest/lockfile. */
const MANIFEST_BASENAMES = new Set([
  "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
  "requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml",
  "go.mod", "Cargo.toml", "Cargo.lock", "pom.xml", "build.gradle",
  "build.gradle.kts", "Gemfile.lock", "composer.json", "composer.lock",
  "packages.config", "pubspec.yaml", "mix.lock", "Package.resolved",
]);
const MANIFEST_EXTS = new Set([".csproj", ".fsproj", ".vbproj"]);

function isManifest(file) {
  const base = file.split("/").pop() || "";
  if (MANIFEST_BASENAMES.has(base)) return true;
  const dot = base.lastIndexOf(".");
  return dot > -1 && MANIFEST_EXTS.has(base.slice(dot));
}

// ─── Git ─────────────────────────────────────────────────────────────────────

function git(args) {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}

function gitContext() {
  let root, branch, commit, remote;
  try {
    root = git(["rev-parse", "--show-toplevel"]);
  } catch {
    fail("not inside a git repository");
  }
  try {
    branch = git(["rev-parse", "--abbrev-ref", "HEAD"]);
  } catch {
    branch = "HEAD";
  }
  try {
    commit = git(["rev-parse", "HEAD"]);
  } catch {
    fail("no commits yet — commit before scanning a pre-push snapshot");
  }
  try {
    remote = git(["config", "--get", "remote.origin.url"]);
  } catch {
    remote = "";
  }
  return { root, branch, commit, remote };
}

/** A stable, human-readable name for the ephemeral dev-scan project. */
function projectName(remote, root) {
  let base = "";
  if (remote) {
    base = remote
      .replace(/\.git$/, "")
      .replace(/^git@[^:]+:/, "")
      .replace(/^https?:\/\/[^/]+\//, "");
  }
  if (!base) base = root.split("/").pop() || "repo";
  return `${base} (dev scan)`;
}

/**
 * Files to scan in --diff mode: what changed vs the base, plus every dependency
 * manifest/lockfile (unchanged or not) so the cloud SCA still sees the full
 * dependency set. Pure so it can be tested without a repo.
 */
function diffFileSet(changed, tracked) {
  const set = new Set(changed.filter(Boolean));
  for (const f of tracked) if (isManifest(f)) set.add(f);
  return [...set];
}

function changedFiles(base) {
  // ACMR = added/copied/modified/renamed; deletions are not scannable.
  const out = git([
    "diff",
    "--name-only",
    "--diff-filter=ACMR",
    `${base}...HEAD`,
  ]);
  return out ? out.split("\n") : [];
}

function trackedFiles() {
  const out = git(["ls-files"]);
  return out ? out.split("\n") : [];
}

const TMP = process.env.TMPDIR || "/tmp";

/** Tarball of the exact tree that will be pushed: tracked files at HEAD. */
function archiveHead(commit) {
  const out = join(TMP, `pepper-scan-${commit.slice(0, 12)}.tar.gz`);
  git(["archive", "--format=tar.gz", "-o", out, "HEAD"]);
  return out;
}

/** Tarball of a specific set of paths at HEAD (for --diff). */
function archiveFiles(commit, paths) {
  if (paths.length === 0) return archiveHead(commit);
  const out = join(TMP, `pepper-scan-${commit.slice(0, 12)}-diff.tar.gz`);
  // Pass paths as pathspecs; only those that exist at HEAD are included.
  git(["archive", "--format=tar.gz", "-o", out, "HEAD", "--", ...paths]);
  return out;
}

// ─── API ─────────────────────────────────────────────────────────────────────

function fail(msg) {
  process.stderr.write(`pepper: ${msg}\n`);
  process.exit(2);
}

async function api(cfg, path, init = {}) {
  const res = await fetch(`${cfg.url}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${cfg.key}`, ...(init.headers || {}) },
  });
  return res;
}

async function createScan(cfg, ctx, scanType, diffBase) {
  let tarball;
  let resolved = null;
  if (diffBase) {
    try {
      resolved = git(["rev-parse", diffBase]);
    } catch {
      // New branch / no upstream: fall back to a full scan rather than failing,
      // so a pre-push hook still works on the first push of a branch.
      process.stderr.write(
        `pepper: --diff base '${diffBase}' not found; scanning full tree\n`,
      );
    }
  }
  if (resolved) {
    const files = diffFileSet(changedFiles(resolved), trackedFiles());
    if (files.length === 0) {
      process.stderr.write("pepper: no changed files vs base; nothing to scan\n");
      process.exit(0);
    }
    tarball = archiveFiles(ctx.commit, files);
  } else {
    tarball = archiveHead(ctx.commit);
  }
  const buf = readFileSync(tarball);
  const form = new FormData();
  form.append("file", new Blob([buf]), "source.tar.gz");
  form.append(
    "data",
    JSON.stringify({
      scanType,
      newProjectName: projectName(ctx.remote, ctx.root),
      branch: ctx.branch,
      commitSha: ctx.commit,
      origin: "LOCAL",
      ephemeral: true,
    }),
  );

  const res = await api(cfg, "/api/scans", { method: "POST", body: form });
  if (res.status === 401) fail("unauthorized — check PEPPER_API_KEY");
  if (!res.ok) fail(`scan create failed (${res.status}): ${await res.text()}`);
  return (await res.json()).scanId;
}

const TERMINAL = new Set(["COMPLETED", "FAILED", "CANCELLED", "STOPPED"]);

async function pollScan(cfg, scanId, onProgress) {
  let last = "";
  for (;;) {
    const res = await api(cfg, `/api/scans/${scanId}`);
    if (!res.ok) fail(`status check failed (${res.status})`);
    const scan = await res.json();
    if (scan.status !== last) {
      onProgress(scan.status);
      last = scan.status;
    }
    if (TERMINAL.has(scan.status)) return scan;
    await new Promise((r) => setTimeout(r, 3000));
  }
}

async function fetchSummary(cfg, scanId) {
  const res = await api(
    cfg,
    `/api/scans/${scanId}/findings?limit=1&page=1`,
  );
  if (!res.ok) return { scannerCounts: {}, total: 0 };
  const data = await res.json();
  return {
    scannerCounts: data.scannerCounts || {},
    total: data.pagination?.total ?? 0,
  };
}

async function download(cfg, scanId, dir) {
  mkdirSync(dir, { recursive: true });
  const targets = [
    [`/api/scans/${scanId}/findings/export?format=csv`, "findings.csv"],
    [`/api/scans/${scanId}/findings/export?format=pdf`, "report.pdf"],
    [`/api/scans/${scanId}/artifacts/cyclonedx`, "sbom.cyclonedx.json"],
    [`/api/scans/${scanId}/artifacts/spdx`, "sbom.spdx.json"],
    [`/api/scans/${scanId}/artifacts/openvex`, "openvex.json"],
    [`/api/scans/${scanId}/artifacts/sarif`, "findings.sarif.json"],
  ];
  const saved = [];
  for (const [path, name] of targets) {
    try {
      const res = await api(cfg, path);
      if (!res.ok) continue;
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length === 0) continue;
      writeFileSync(join(dir, name), buf);
      saved.push(name);
    } catch {
      /* artifact not available for this scan type; skip */
    }
  }
  return saved;
}

// ─── Main ────────────────────────────────────────────────────────────────────

export { parseArgs, projectName, diffFileSet, isManifest, hookScript };

/** Body of the generated .git/hooks/pre-push. */
function hookScript(cliPath, gate) {
  const flags = gate ? "--diff @{upstream} --gate" : "--diff @{upstream} --wait=false";
  // Advisory install ends with `|| true` so it can never block a push; the gate
  // install omits it so a failed gate (exit 1) refuses the push.
  const tail = gate ? "" : " || true";
  return `#!/usr/bin/env bash
# Pepper pre-push scan (installed by 'pepper-scan install-hook').
# Skip once with: git push --no-verify
[ -n "$PEPPER_SKIP" ] && exit 0
node "${cliPath}" ${flags}${tail}
`;
}

function installHook(opts) {
  let hooksDir;
  try {
    hooksDir = git(["rev-parse", "--git-path", "hooks"]);
  } catch {
    fail("not inside a git repository");
  }
  const root = git(["rev-parse", "--show-toplevel"]);
  const abs = hooksDir.startsWith("/") ? hooksDir : join(root, hooksDir);
  mkdirSync(abs, { recursive: true });
  const hookPath = join(abs, "pre-push");
  const cliPath = new URL(import.meta.url).pathname;

  if (existsSync(hookPath)) {
    const current = readFileSync(hookPath, "utf8");
    if (!current.includes("Pepper pre-push scan")) {
      fail(
        `a pre-push hook already exists at ${hookPath}; ` +
          "remove or merge it before installing",
      );
    }
  }
  writeFileSync(hookPath, hookScript(cliPath, opts.gate), { mode: 0o755 });
  process.stdout.write(
    `Installed pre-push hook → ${hookPath}\n` +
      `  mode: ${opts.gate ? "gate (blocks push on gate failure)" : "advisory (non-blocking)"}\n` +
      `  skip once: git push --no-verify  ·  or  PEPPER_SKIP=1 git push\n`,
  );
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.command === "install-hook") {
    installHook(opts);
    return;
  }
  if (opts.command !== "scan") fail(`unknown command '${opts.command}'`);

  const cfg = loadConfig();
  if (!cfg.key) fail("PEPPER_API_KEY not set (env or ~/.pepper/config)");

  const scanType = opts.type || cfg.scanType || "FULL";
  const ctx = gitContext();

  process.stderr.write(
    `pepper · ${scanType} scan of ${ctx.branch}@${ctx.commit.slice(0, 8)} → ${cfg.url}\n`,
  );

  const scanId = await createScan(cfg, ctx, scanType, opts.diff);
  const scanUrl = `${cfg.url}/scans/${scanId}`;

  if (!opts.wait) {
    process.stdout.write(opts.json ? JSON.stringify({ scanId, scanUrl }) + "\n" : `Queued: ${scanUrl}\n`);
    return;
  }

  const scan = await pollScan(cfg, scanId, (status) =>
    process.stderr.write(`  ${status.toLowerCase()}\n`),
  );

  if (scan.status !== "COMPLETED") {
    fail(`scan ${scan.status.toLowerCase()}`);
  }

  const summary = await fetchSummary(cfg, scanId);
  const gateFailed = scan.gateResult === "FAILED";
  const counts = {
    CRITICAL: scan.criticalCount ?? 0,
    HIGH: scan.highCount ?? 0,
    MEDIUM: scan.mediumCount ?? 0,
    LOW: scan.lowCount ?? 0,
  };

  let downloaded = [];
  if (opts.download) downloaded = await download(cfg, scanId, opts.download);

  if (opts.json) {
    process.stdout.write(
      JSON.stringify({
        scanId,
        scanUrl,
        status: scan.status,
        gateResult: scan.gateResult,
        counts,
        scannerCounts: summary.scannerCounts,
        downloaded,
      }) + "\n",
    );
  } else {
    process.stdout.write(
      `\nResult: ${counts.CRITICAL} CRITICAL · ${counts.HIGH} HIGH · ` +
        `${counts.MEDIUM} MEDIUM · ${counts.LOW} LOW` +
        (scan.gateResult ? `   (gate: ${scan.gateResult})` : "") +
        `\nReport: ${scanUrl}\n`,
    );
    if (downloaded.length) {
      process.stdout.write(`Downloaded to ${opts.download}: ${downloaded.join(", ")}\n`);
    }
  }

  // Advisory by default: a failed gate only fails the command with --gate.
  if (opts.gate && gateFailed) process.exit(1);
}

// Run only when executed directly, so tests can import the pure helpers above.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
}
