#!/usr/bin/env node
/**
 * Mock Azure DevOps Server — for testing Pepper's on-prem ADO integration
 * locally without a real (Windows) Azure DevOps Server.
 *
 * It implements the small slice of the ADO REST API that Pepper calls AND serves
 * a real sample git repository over smart HTTP, so the whole path works:
 *
 *   connect (serverUrl) → list/import repo → git clone → SAST scan →
 *   PR status + inline threads posted back (printed to this console)
 *
 * Run it, then in Pepper connect Azure DevOps with:
 *   Organization / collection : DefaultCollection   (or --collection)
 *   Server URL                : http://localhost:8088   (this process)
 *   Personal Access Token     : any non-empty value (the mock ignores it)
 *
 * Requirements: `git` on PATH (used for the sample repo + `git http-backend`).
 *
 * Usage:
 *   node scripts/ado-server-mock.mjs [--port 8088] [--collection DefaultCollection]
 *                                    [--project TestProject] [--repo testrepo]
 */

import http from "node:http";
import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function parseArgs(argv) {
  const a = {
    port: 8088,
    collection: "DefaultCollection",
    project: "TestProject",
    repo: "testrepo",
  };
  for (let i = 0; i < argv.length; i++) {
    const n = () => argv[++i];
    if (argv[i] === "--port") a.port = Number(n());
    else if (argv[i] === "--collection") a.collection = n();
    else if (argv[i] === "--project") a.project = n();
    else if (argv[i] === "--repo") a.repo = n();
    else if (argv[i] === "--advertise-base") a.advertiseBase = n();
  }
  return a;
}

const cfg = parseArgs(process.argv.slice(2));
const REPO_ID = "11111111-2222-3333-4444-555555555555";
const VULN_FILE = "src/login.js";

// ── Build a sample repo + bare repo served over smart HTTP ──────────────────
const root = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-ado-mock-"));
const gitRoot = path.join(root, "git");
fs.mkdirSync(gitRoot, { recursive: true });

function git(args, cwd) {
  execFileSync("git", args, {
    cwd,
    stdio: "pipe",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "Mock",
      GIT_AUTHOR_EMAIL: "mock@example.com",
      GIT_COMMITTER_NAME: "Mock",
      GIT_COMMITTER_EMAIL: "mock@example.com",
    },
  });
}

function buildSampleRepo() {
  const src = path.join(root, "src-work");
  fs.mkdirSync(path.join(src, "src"), { recursive: true });
  // A deliberately vulnerable file so SAST has something to find.
  fs.writeFileSync(
    path.join(src, VULN_FILE),
    [
      "const { exec } = require('child_process');",
      "function login(req, res) {",
      "  const user = req.query.user;",
      "  // SQL injection: user input concatenated into a query",
      "  const q = \"SELECT * FROM users WHERE name = '\" + user + \"'\";",
      "  db.query(q);",
      "  // Command injection: user input to a shell",
      "  exec('echo ' + req.query.msg);",
      "  // Code injection",
      "  eval(req.query.expr);",
      "}",
      "module.exports = { login };",
      "",
    ].join("\n"),
  );
  fs.writeFileSync(
    path.join(src, "README.md"),
    "# Mock ADO test repo\nUsed by scripts/ado-server-mock.mjs.\n",
  );
  git(["init", "-b", "main"], src);
  git(["add", "."], src);
  git(["commit", "-m", "Initial commit with sample vulnerabilities"], src);
  // Bare repo that http-backend will serve.
  git(["clone", "--bare", src, path.join(gitRoot, `${cfg.repo}.git`)], root);
}

buildSampleRepo();

// ── Helpers ─────────────────────────────────────────────────────────────────
const base = `http://localhost:${cfg.port}`;
// The URL advertised to Pepper for cloning/remoteUrl. When Pepper runs in
// Docker and the mock runs on the host, pass --advertise-base
// http://host.docker.internal:<port> so the container can reach it.
const advertiseBase = cfg.advertiseBase || base;
const cloneUrl = `${advertiseBase}/${cfg.collection}/${cfg.project}/_git/${cfg.repo}`;

function json(res, status, body) {
  const s = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(s),
  });
  res.end(s);
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

// ── git smart HTTP via `git http-backend` (CGI) ─────────────────────────────
function serveGit(req, res, u) {
  const marker = `/_git/${cfg.repo}`;
  const idx = u.pathname.indexOf(marker);
  const gitSub = u.pathname.slice(idx + marker.length); // e.g. /info/refs
  const env = {
    ...process.env,
    GIT_HTTP_EXPORT_ALL: "1",
    GIT_PROJECT_ROOT: gitRoot,
    PATH_INFO: `/${cfg.repo}.git${gitSub}`,
    REQUEST_METHOD: req.method,
    QUERY_STRING: u.search.replace(/^\?/, ""),
    CONTENT_TYPE: req.headers["content-type"] || "",
    REMOTE_USER: "mock",
  };
  const cgi = spawn("git", ["http-backend"], { env });
  req.pipe(cgi.stdin);

  let head = Buffer.alloc(0);
  let sentHead = false;
  cgi.stdout.on("data", (chunk) => {
    if (sentHead) return res.write(chunk);
    head = Buffer.concat([head, chunk]);
    const sep = head.indexOf("\r\n\r\n");
    if (sep === -1) return;
    const headerBlock = head.slice(0, sep).toString("utf8");
    const rest = head.slice(sep + 4);
    let status = 200;
    const headers = {};
    for (const line of headerBlock.split("\r\n")) {
      const c = line.indexOf(":");
      if (c === -1) continue;
      const k = line.slice(0, c).trim();
      const v = line.slice(c + 1).trim();
      if (k.toLowerCase() === "status") status = parseInt(v, 10) || 200;
      else headers[k] = v;
    }
    res.writeHead(status, headers);
    if (rest.length) res.write(rest);
    sentHead = true;
  });
  cgi.stdout.on("end", () => res.end());
  cgi.stderr.on("data", (d) => process.stderr.write(`[git] ${d}`));
  cgi.on("error", (e) => {
    if (!sentHead) res.writeHead(500);
    res.end(`git http-backend error: ${e.message}`);
  });
}

// ── REST endpoints ──────────────────────────────────────────────────────────
function repoObject() {
  return {
    id: REPO_ID,
    name: cfg.repo,
    project: { name: cfg.project, id: "proj-1" },
    defaultBranch: "refs/heads/main",
    remoteUrl: cloneUrl,
    webUrl: cloneUrl,
  };
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, base);
  const p = u.pathname;

  // git smart HTTP transport (clone)
  if (p.includes(`/_git/${cfg.repo}`)) return serveGit(req, res, u);

  // connectionData (connect probe)
  if (p.endsWith("/_apis/connectionData")) {
    console.log("→ connectionData probe");
    return json(res, 200, {
      authenticatedUser: { providerDisplayName: "Mock User", id: "user-1" },
    });
  }

  // list repositories
  if (p.endsWith("/_apis/git/repositories")) {
    console.log("→ list repositories");
    return json(res, 200, { count: 1, value: [repoObject()] });
  }

  // get single repository
  if (/\/_apis\/git\/repositories\/[^/]+$/.test(p)) {
    console.log("→ get repository");
    return json(res, 200, repoObject());
  }

  // PR iterations
  if (/\/pullRequests\/\d+\/iterations$/.test(p)) {
    return json(res, 200, { count: 1, value: [{ id: 1 }] });
  }
  // PR iteration changes → the vulnerable file, so inline threads can match
  if (/\/pullRequests\/\d+\/iterations\/\d+\/changes$/.test(p)) {
    return json(res, 200, {
      changeEntries: [{ item: { path: `/${VULN_FILE}`, isFolder: false } }],
    });
  }
  // existing threads (dedupe check)
  if (/\/pullRequests\/\d+\/threads$/.test(p) && req.method === "GET") {
    return json(res, 200, { value: [] });
  }
  // POST a new inline thread
  if (/\/pullRequests\/\d+\/threads$/.test(p) && req.method === "POST") {
    const body = JSON.parse((await readBody(req)) || "{}");
    const ctx = body.threadContext || {};
    console.log(
      `📌 PR inline thread → ${ctx.filePath || "?"}:${ctx.rightFileStart?.line ?? "?"}`,
    );
    return json(res, 200, { id: Math.floor(Math.random() * 100000) });
  }
  // POST a PR status check
  if (/\/pullRequests\/\d+\/statuses$/.test(p) && req.method === "POST") {
    const body = JSON.parse((await readBody(req)) || "{}");
    console.log(
      `✅ PR status → state=${body.state} "${body.description || ""}"`,
    );
    return json(res, 200, { id: Math.floor(Math.random() * 100000) });
  }

  console.log(`· unhandled ${req.method} ${p}`);
  return json(res, 200, {});
});

server.listen(cfg.port, () => {
  console.log("─".repeat(64));
  console.log("Mock Azure DevOps Server running");
  console.log(`  Server URL   : ${base}`);
  console.log(`  Collection   : ${cfg.collection}`);
  console.log(`  Project/Repo : ${cfg.project}/${cfg.repo}`);
  console.log(`  Repo GUID    : ${REPO_ID}`);
  console.log(`  Clone URL    : ${cloneUrl}`);
  console.log("─".repeat(64));
  console.log("In Pepper → Settings → Integrations → Azure DevOps → Connect:");
  console.log(`  Organization / collection = ${cfg.collection}`);
  console.log(`  Server URL                = ${base}`);
  console.log("  Personal Access Token     = any-non-empty-value");
  console.log("Then import the repo and run a scan. PR events posted back to");
  console.log("this server are printed above. Ctrl-C to stop.");
});

function cleanup() {
  try {
    fs.rmSync(root, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
  process.exit(0);
}
process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);
