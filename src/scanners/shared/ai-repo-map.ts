/**
 * AI-built repository map shared by every AI scanner in a scan.
 *
 * Replaces the old regex repo context (route/sink/auth regexes that only knew
 * Express/Nest/Django) and the filename-regex zero-day prioritiser. The model
 * explores the repo the way a reviewer would:
 *
 *   1. EXPLORE — it sees the directory tree and the manifests, and picks the
 *      files it needs to understand the system (entry points, routing, auth,
 *      tenancy, money flows, data access).
 *   2. MAP — it reads those files and writes a structured map: architecture,
 *      frameworks, routes and where auth is enforced, tenancy model, trust
 *      boundaries, data stores, sensitive flows, and the highest-risk paths.
 *
 * The map is built once per scan (memoised on the work dir) from the WHOLE
 * repository, so PR scans that only review changed files still know where
 * guards and callers live. If the model is unavailable the map falls back to
 * a path-only layout summary; nothing is ever detected by pattern.
 */
import * as fs from "fs";
import * as path from "path";
import {
  analyzeWithLlm,
  createLlmClient,
  parseLlmJsonResponse,
} from "@/lib/llm-gateway";
import { buildRepoContextSummary } from "@/lib/llm-repo-context";
import { llmExcludedPath } from "@/lib/llm-exclusions";
import {
  LLM_MAX_FILE_SIZE_BYTES,
  LLM_MAX_RESPONSE_TOKENS,
  OLLAMA_MAX_RESPONSE_TOKENS,
} from "@/lib/constants";
import { logger } from "@/lib/logger";
import { UNTRUSTED_CONTENT_GUARD } from "./prompts";
import type { ScanContext } from "../types";

/** Files the model may ask to read while mapping. */
const MAX_EXPLORE_FILES = parseInt(process.env.REPO_MAP_MAX_FILES || "40", 10);
/** Characters of each explored file sent to the model. */
const MAX_FILE_CHARS = parseInt(process.env.REPO_MAP_FILE_CHARS || "8000", 10);
/** Total characters of explored file content in the MAP call. */
const MAX_TOTAL_CHARS = parseInt(process.env.REPO_MAP_TOTAL_CHARS || "160000", 10);
/** Characters of the directory tree sent to the model. */
const MAX_TREE_CHARS = 40000;
/** Characters of the rendered map handed to the scanners. */
const MAX_SUMMARY_CHARS = 14000;

/** Basenames read as manifests so the model knows the stack before exploring. */
const MANIFESTS = new Set([
  "package.json",
  "cargo.toml",
  "go.mod",
  "pyproject.toml",
  "requirements.txt",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "composer.json",
  "gemfile",
  "readme.md",
]);

export interface RepoMap {
  /** Text block prepended to every AI scanner prompt. */
  summary: string;
  /** Repo-relative files the model ranked as highest risk, most risky first. */
  highRiskFiles: string[];
  /** "ai" when the model built it, "fallback" when it could not. */
  source: "ai" | "fallback";
}

interface MapRoute {
  method?: string;
  path?: string;
  handler?: string;
  file?: string;
  auth?: string;
}

interface MapAnswer {
  architecture?: string;
  languages?: string[];
  frameworks?: string[];
  entryPoints?: string[];
  routes?: MapRoute[];
  authModel?: { mechanisms?: string[]; enforcedAt?: string[]; gaps?: string[] };
  tenancy?: string;
  trustBoundaries?: string[];
  dataStores?: string[];
  sensitiveFlows?: string[];
  highRiskFiles?: Array<{ path?: string; reason?: string } | string>;
}

const EXPLORE_PROMPT = `You are a principal application-security engineer starting a review of an unfamiliar repository.
You are given its directory tree and its manifests. Choose the files you must read to understand how the system works and where it can be attacked:
entry points and server bootstrap, route/handler registration, authentication and authorization (middleware, extractors, guards, policies),
tenant/merchant/org scoping, money or state-changing flows (payments, refunds, transfers, workflows), webhook handlers, data-access layers,
deserialization and outbound-request helpers, configuration that changes security behaviour.
Prefer files that explain MANY other files (routers, middleware, shared auth helpers) over leaf code. Skip tests, fixtures, docs and generated code.
Return ONLY JSON: {"files": ["repo/relative/path", ...]} with at most ${MAX_EXPLORE_FILES} paths copied exactly from the tree.${UNTRUSTED_CONTENT_GUARD}`;

const MAP_PROMPT = `You are a principal application-security engineer. From the directory tree, manifests and the files you chose to read, write the security map of this repository that other reviewers will rely on while they review individual files.
Be concrete and only state what the code shows; when something is inferred, say "likely". Name real files, functions, extractors and middleware.
Return ONLY JSON with this shape:
{
  "architecture": "2-4 sentences: what the system does, main components/services/crates and how requests flow through them",
  "languages": ["..."],
  "frameworks": ["web/ORM/RPC frameworks with versions if visible"],
  "entryPoints": ["file: what starts there"],
  "routes": [{"method": "GET|POST|...|ANY", "path": "/v1/...", "handler": "fn or class", "file": "path", "auth": "how this route is authenticated/authorized, or 'none visible'"}],
  "authModel": {"mechanisms": ["API key, JWT, session, mTLS, ..."], "enforcedAt": ["file/function where auth is applied and how routes opt in"], "gaps": ["routes or areas where auth or ownership checks look missing or inconsistent"]},
  "tenancy": "how tenant/merchant/org/user scoping is derived and enforced on data access",
  "trustBoundaries": ["external inputs: public API, webhooks, admin API, queues, third-party callbacks, LLM/tool calls"],
  "dataStores": ["databases, caches, queues, object stores and the access layer used"],
  "sensitiveFlows": ["money movement, credential handling, PII/card data, privilege changes — with files"],
  "highRiskFiles": [{"path": "repo/relative/path or directory/", "reason": "why an attacker would target it"}]
}
List up to 60 routes (most security-relevant first) and up to 80 highRiskFiles ordered most risky first; a directory path ending in "/" means every file under it.${UNTRUSTED_CONTENT_GUARD}`;

const cache = new Map<string, Promise<RepoMap>>();

/**
 * The repository map for this scan. Concurrent scanners share one build; the
 * whole-repo file list (ctx.repoFileList) is used when present.
 */
export function getRepoMap(ctx: ScanContext): Promise<RepoMap> {
  const key = ctx.scanId ? `${ctx.scanId}:${ctx.workDir}` : ctx.workDir;
  let hit = cache.get(key);
  if (!hit) {
    hit = buildRepoMap(ctx);
    cache.set(key, hit);
  }
  return hit;
}

/** Drop a scan's cached map (called when the scan finishes, and by tests). */
export function forgetRepoMap(ctx?: Pick<ScanContext, "scanId" | "workDir">): void {
  if (!ctx) {
    cache.clear();
    return;
  }
  cache.delete(ctx.scanId ? `${ctx.scanId}:${ctx.workDir}` : ctx.workDir);
}

function fallbackMap(files: string[]): RepoMap {
  return { summary: buildRepoContextSummary(files), highRiskFiles: [], source: "fallback" };
}

async function buildRepoMap(ctx: ScanContext): Promise<RepoMap> {
  const files = ctx.repoFileList ?? ctx.fileList;
  if (files.length === 0) return fallbackMap(files);
  const isOllama = ctx.orgSettings.llmProvider.toLowerCase() === "ollama";
  if (!ctx.orgSettings.llmApiKey?.trim() && !isOllama) return fallbackMap(files);

  const client = createLlmClient({
    provider: ctx.orgSettings.llmProvider,
    baseUrl: ctx.orgSettings.llmBaseUrl,
    apiKey: ctx.orgSettings.llmApiKey,
    model: ctx.orgSettings.llmModel,
  });
  const maxTokens = isOllama ? OLLAMA_MAX_RESPONSE_TOKENS : LLM_MAX_RESPONSE_TOKENS;
  const known = new Set(files);

  try {
    ctx.onProgress?.("AI repo map: exploring repository structure...");
    const tree = renderTree(files);
    const manifests = readManifests(ctx.workDir, files);
    const overview = `DIRECTORY TREE (${files.length} files):\n${tree}\n\nMANIFESTS:\n${manifests}`;

    const explore = parseLlmJsonResponse<{ files?: unknown }>(
      await analyzeWithLlm(client, ctx.orgSettings.llmModel, EXPLORE_PROMPT, overview, { maxTokens }),
      {},
    );
    const chosen = (Array.isArray(explore.files) ? explore.files : [])
      .filter((f): f is string => typeof f === "string")
      .map(normalizePath)
      .filter((f) => known.has(f) && !llmExcludedPath(f))
      .slice(0, MAX_EXPLORE_FILES);

    ctx.onProgress?.(`AI repo map: reading ${chosen.length} key files...`);
    const bundle = readBundle(ctx.workDir, chosen);
    const answer = parseLlmJsonResponse<MapAnswer>(
      await analyzeWithLlm(
        client,
        ctx.orgSettings.llmModel,
        MAP_PROMPT,
        `${overview}\n\nFILES READ:\n${bundle}`,
        { maxTokens },
      ),
      {},
    );
    if (!answer.architecture && !answer.routes?.length && !answer.highRiskFiles?.length) {
      logger.warn({ chosen: chosen.length }, "AI repo map returned no usable map; using path summary");
      return fallbackMap(files);
    }

    const highRiskFiles = expandRiskPaths(answer.highRiskFiles ?? [], files);
    logger.info(
      { routes: answer.routes?.length ?? 0, highRiskFiles: highRiskFiles.length, explored: chosen.length },
      "AI repo map built",
    );
    return { summary: renderMap(answer, files.length), highRiskFiles, source: "ai" };
  } catch (err) {
    logger.warn({ err }, "AI repo map failed; using path summary");
    return fallbackMap(files);
  }
}

function normalizePath(p: string): string {
  return p.trim().replace(/\\/g, "/").replace(/^\.?\/+/, "");
}

/**
 * Directory tree with file counts. Small repos list every file; large repos
 * list directories (with counts) and the files of shallow directories so the
 * tree stays inside the budget.
 */
export function renderTree(files: string[], maxChars = MAX_TREE_CHARS): string {
  const sorted = [...files].map(normalizePath).sort();
  const full = sorted.join("\n");
  if (full.length <= maxChars) return full;

  const dirCounts = new Map<string, number>();
  for (const f of sorted) {
    const parts = f.split("/");
    for (let i = 1; i < parts.length; i++) {
      const dir = parts.slice(0, i).join("/") + "/";
      dirCounts.set(dir, (dirCounts.get(dir) ?? 0) + 1);
    }
  }
  for (let depth = 6; depth >= 1; depth--) {
    const lines: string[] = [];
    for (const [dir, count] of [...dirCounts].sort(([a], [b]) => a.localeCompare(b))) {
      if (dir.split("/").length - 1 <= depth) lines.push(`${dir} (${count} files)`);
    }
    const rootFiles = sorted.filter((f) => !f.includes("/"));
    const out = [...rootFiles, ...lines].join("\n");
    if (out.length <= maxChars) return out;
  }
  return sorted.slice(0, 2000).join("\n").slice(0, maxChars);
}

function readManifests(workDir: string, files: string[]): string {
  const picked = files
    .filter((f) => MANIFESTS.has(path.basename(f).toLowerCase()))
    .sort((a, b) => a.split("/").length - b.split("/").length)
    .slice(0, 12);
  return picked
    .map((f) => {
      const text = safeRead(workDir, f);
      return text ? `### ${f}\n${text.slice(0, 3000)}` : "";
    })
    .filter(Boolean)
    .join("\n\n");
}

function readBundle(workDir: string, files: string[]): string {
  let total = 0;
  const parts: string[] = [];
  for (const f of files) {
    if (total >= MAX_TOTAL_CHARS) break;
    const text = safeRead(workDir, f);
    if (!text) continue;
    const slice = text.slice(0, Math.min(MAX_FILE_CHARS, MAX_TOTAL_CHARS - total));
    total += slice.length;
    parts.push(`### ${f}\n\`\`\`\n${slice}\n\`\`\``);
  }
  return parts.join("\n\n");
}

function safeRead(workDir: string, rel: string): string {
  try {
    const full = path.join(workDir, rel);
    if (fs.statSync(full).size > LLM_MAX_FILE_SIZE_BYTES) return "";
    return fs.readFileSync(full, "utf-8");
  } catch {
    return "";
  }
}

/** Resolve the model's ranked paths (files or "dir/") to real files, in order. */
export function expandRiskPaths(
  entries: Array<{ path?: string; reason?: string } | string>,
  files: string[],
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const normalized = files.map(normalizePath);
  const known = new Set(normalized);
  for (const e of entries) {
    const raw = typeof e === "string" ? e : e?.path;
    if (!raw) continue;
    const p = normalizePath(raw);
    const matches = known.has(p)
      ? [p]
      : normalized.filter((f) => f.startsWith(p.endsWith("/") ? p : `${p}/`));
    for (const m of matches) {
      if (!seen.has(m)) {
        seen.add(m);
        out.push(m);
      }
    }
  }
  return out;
}

function renderMap(m: MapAnswer, fileCount: number): string {
  const list = (title: string, items?: string[]) =>
    items?.length ? `\n${title}:\n${items.map((i) => `  - ${i}`).join("\n")}\n` : "";
  let out = `REPOSITORY SECURITY MAP (built by AI from the whole repository, ${fileCount} files)\n`;
  if (m.architecture) out += `\nARCHITECTURE: ${m.architecture}\n`;
  if (m.languages?.length) out += `LANGUAGES: ${m.languages.join(", ")}\n`;
  if (m.frameworks?.length) out += `FRAMEWORKS: ${m.frameworks.join(", ")}\n`;
  out += list("ENTRY POINTS", m.entryPoints);
  if (m.authModel) {
    out += list("AUTH MECHANISMS", m.authModel.mechanisms);
    out += list("AUTH ENFORCED AT", m.authModel.enforcedAt);
    out += list("SUSPECTED AUTH GAPS (verify in code)", m.authModel.gaps);
  }
  if (m.tenancy) out += `\nTENANCY: ${m.tenancy}\n`;
  out += list("TRUST BOUNDARIES", m.trustBoundaries);
  out += list("DATA STORES", m.dataStores);
  out += list("SENSITIVE FLOWS", m.sensitiveFlows);
  if (m.routes?.length) {
    out += `\nROUTES:\n`;
    for (const r of m.routes.slice(0, 60)) {
      out += `  ${r.method ?? "ANY"} ${r.path ?? "?"} → ${r.handler ?? "?"} (${r.file ?? "?"}) auth: ${r.auth ?? "unknown"}\n`;
    }
  }
  out += `\nUse this map to locate guards, callers and tenant scoping that live outside the code you are reviewing. It is context, not evidence: every finding must still cite lines from the code shown.\n`;
  return out.length > MAX_SUMMARY_CHARS ? `${out.slice(0, MAX_SUMMARY_CHARS - 20)}\n… [map truncated]\n` : out;
}
