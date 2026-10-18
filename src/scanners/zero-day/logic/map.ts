/**
 * Map pass (docs/LOGIC_FLAW_DETECTION_SPEC.md §4.1–4.2): the model reads the
 * code and reports facts in a fixed structure — entry points, their guards and
 * data access, where ownership is recorded, and traits of security-relevant
 * functions. It reports what is there, never whether it is wrong, so the
 * structure works for any language or framework. Every cited line is then
 * checked against the source; facts that don't verify are discarded.
 */
import * as path from "path";
import { FILE_EXTENSIONS, SKIP_DIRECTORIES, BINARY_EXTENSIONS } from "@/lib/constants";
import { llmExcludedPath } from "@/lib/llm-exclusions";
import { isTestLikePath } from "@/lib/test-paths";
import { UNTRUSTED_CONTENT_GUARD } from "../../shared/prompts";
import { SourceFiles, resolveKnownFile, verifyQuote } from "./source";

export type EntryKind = "http" | "graphql" | "rpc" | "webhook" | "job" | "consumer" | "cron" | "cli" | "other";
export type GuardKind = "authn" | "role" | "owner" | "other";
export type Filter = "caller-identity" | "request-input" | "both" | "none" | "unclear";
export type Trait =
  | "security-check-error-path"
  | "external-event-side-effect"
  | "cache-or-shared-state"
  | "job-loads-by-payload-id"
  | "read-then-write-value"
  | "money-arithmetic";

export const TRAITS: Trait[] = [
  "security-check-error-path",
  "external-event-side-effect",
  "cache-or-shared-state",
  "job-loads-by-payload-id",
  "read-then-write-value",
  "money-arithmetic",
];

export interface Loc { file: string; line: number; quote: string }
export interface Guard extends Loc { name: string; kind: GuardKind; scope: "route" | "group" | "global" | "in-handler"; order: "before" | "after" | "unclear" }
export interface DataAccess extends Loc { resource: string; filteredBy: Filter; op: "read" | "write" | "delete" }
export interface EntryPoint extends Loc {
  id: string;
  kind: EntryKind;
  method: string;
  path: string;
  handler: { file: string; startLine: number; endLine: number; name: string } | null;
  guards: Guard[];
  dataAccess: DataAccess[];
  takesObjectId: boolean;
  privileged: boolean;
  public: boolean;
}
export interface Ownership extends Loc { resource: string }
export interface TraitRegion { trait: Trait; file: string; startLine: number; endLine: number; quote: string }

export interface LogicMap {
  entryPoints: EntryPoint[];
  ownership: Ownership[];
  traits: TraitRegion[];
  filesRead: string[];
  ledger: MapLedger;
}
export interface MapLedger {
  batches: number;
  batchesFailed: number;
  entryPointsReported: number;
  entryPointsKept: number;
  factsDiscarded: number;
  traitsKept: number;
}

// ─── File selection ─────────────────────────────────────────────────────────

const NAME_HINT =
  /(?:^|[/_.-])(route|routes|router|controller|controllers|handler|handlers|view|views|api|resolver|resolvers|endpoint|endpoints|webhook|webhooks|job|jobs|worker|workers|consumer|consumers|task|tasks|middleware|middlewares|auth|policy|policies|permission|permissions|guard|guards|server|app|main|urls|service|services)(?:[/_.-]|$)/i;
const CONTENT_HINTS: RegExp[] = [
  /\b(?:get|post|put|patch|delete)\b\s*\(?\s*['"`]\//i, // verb next to a path string
  /['"`]\/[\w:{}<>/-]*['"`]/, // a path literal
  /^\s*(?:@|\[)\w+(?:Mapping|Route|Get|Post|Put|Patch|Delete|Http\w*)?\b/m, // decorators / annotations / attributes
  /\b(?:router|app|server|r|e|g|mux|api)\.(?:get|post|put|patch|delete|use|route|group|handle\w*)\s*\(/i,
  /\b(?:req|request|res|response|ctx|context|w http\.ResponseWriter)\b/,
  /\b(?:session|token|jwt|current_?user|principal|permission|role|admin|tenant|owner)\b/i,
  /\b(?:balance|amount|price|refund|payment|webhook|cache|queue|job|cron|schedule)\b/i,
];

function isSource(file: string): boolean {
  const ext = path.extname(file).toLowerCase();
  if (BINARY_EXTENSIONS.has(ext)) return false;
  if (!FILE_EXTENSIONS[ext]) return false;
  if (file.split(/[\\/]/).some((p) => SKIP_DIRECTORIES.has(p))) return false;
  if (isTestLikePath(file)) return false;
  if (/(?:^|\/)(?:generated|__generated__|migrations?)\//i.test(file) || /\.min\.js$|\.d\.ts$/i.test(file)) return false;
  // API client collections and request files describe calls to the app, not entry points.
  if (/postman_collection|insomnia|\.http$|\.rest$|(?:^|\/)(?:docs?|examples?)\//i.test(file)) return false;
  return !llmExcludedPath(file);
}

/** Source files ranked for the map pass: names and content that suggest entry points first. */
export function selectMapFiles(src: SourceFiles, fileList: string[], max: number): { selected: string[]; sourceCount: number } {
  const scored: Array<{ file: string; score: number }> = [];
  let sourceCount = 0;
  for (const file of fileList) {
    if (!isSource(file)) continue;
    sourceCount++;
    const lines = src.lines(file);
    if (!lines || !lines.join("").trim()) continue;
    const text = lines.slice(0, 400).join("\n");
    let score = NAME_HINT.test(file) ? 3 : 0;
    for (const re of CONTENT_HINTS) if (re.test(text)) score++;
    scored.push({ file, score });
  }
  scored.sort((a, b) => b.score - a.score || a.file.localeCompare(b.file));
  return { selected: scored.slice(0, max).map((s) => s.file), sourceCount };
}

/** Files into batches of about `budgetChars` of numbered source; big files are split. */
export function batchFiles(src: SourceFiles, files: string[], budgetChars: number): Array<Array<{ file: string; start: number; end: number }>> {
  const batches: Array<Array<{ file: string; start: number; end: number }>> = [];
  let current: Array<{ file: string; start: number; end: number }> = [];
  let used = 0;
  const push = () => {
    if (current.length) batches.push(current);
    current = [];
    used = 0;
  };
  for (const file of files) {
    const lines = src.lines(file) ?? [];
    let start = 1;
    while (start <= lines.length) {
      let end = start;
      let size = 0;
      while (end <= lines.length && size + lines[end - 1].length + 8 <= budgetChars) {
        size += lines[end - 1].length + 8;
        end++;
      }
      end = Math.max(start, end - 1);
      if (used + size > budgetChars) push();
      current.push({ file, start, end });
      used += size;
      start = end + 1;
    }
  }
  push();
  return batches;
}

// ─── Prompt ─────────────────────────────────────────────────────────────────

export const MAP_SYSTEM_PROMPT = `You map the attack surface of an application from its source code. You report FACTS that are in the code, with exact line numbers and a short verbatim quote of each cited line. You do NOT judge whether anything is a vulnerability.

${UNTRUSTED_CONTENT_GUARD}

The code may be in any language and use any framework, router, decorator style, wrapper function, configuration file (for example an OpenAPI spec with operationId) or convention. Work out how THIS code registers entry points and applies checks.

Report:

1. entryPoints — every place where outside input enters: HTTP routes, GraphQL resolvers, RPC methods, webhooks and callbacks, queue consumers, background jobs, scheduled tasks, CLI commands. For each:
   - kind: http | graphql | rpc | webhook | job | consumer | cron | cli | other
   - method: GET/POST/… for HTTP, otherwise the queue, job or command name
   - path: the route as declared ("" if not visible)
   - file, line, quote: where it is registered or declared
   - handler: {file, startLine, endLine, name} of the code that runs, if visible in the provided files; else null
   - guards: every check that applies BEFORE OR AROUND the handler: middleware, decorators, annotations, wrapper functions, router- or group-level middleware, global middleware, and checks at the top of the handler body. For each: name, kind (authn = is there a logged-in caller; role = admin/role/permission/scope; owner = the caller owns this object; other = rate limit, logging, CSRF, validation…), scope (route | group | global | in-handler), order (before = runs before the handler acts; after = listed or registered after the handler, so it runs only after the handler has already acted or responded; unclear), file, line, quote.
   - dataAccess: each read/write/delete of stored data in the handler (database, ORM, store, file). For each: resource (the table, model or collection name), op (read | write | delete), filteredBy (caller-identity = the lookup is restricted by the authenticated caller: session user, verified token subject, principal; request-input = selected only by values from the request: path, query, body, headers, cookies, job payload; both; none; unclear), file, line, quote.
   - takesObjectId: true if a value from the request (id, name, slug, key) selects which object is read or changed
   - privileged: true for admin, setup, reset, debug, logs, system info, configuration, user lists and bulk exports
   - public: true if it is meant for anonymous callers (login, register, logout, health, docs, password-reset request, public catalog)
2. ownership — places where the code records who owns a resource: an owner/user/tenant field set from the caller's identity when creating it, or an owner column in a model. resource, file, line, quote.
3. traits — functions that do one of these (file, startLine, endLine of the function, quote of its first line):
   - security-check-error-path: authentication, authorization, signature or verification code with an error/exception path or a missing-configuration branch
   - external-event-side-effect: a webhook, callback, payment notification or message consumer that credits, refunds, fulfils, sends or changes balances or state
   - cache-or-shared-state: reads or writes a cache, memo or module-level/global variable with per-user or per-tenant data
   - job-loads-by-payload-id: a job or consumer that loads or changes records by an id taken from its payload
   - read-then-write-value: reads a balance, stock, quota, credit, counter or single-use flag and then writes a value computed from it
   - money-arithmetic: parses, computes or compares amounts, prices, totals, fees or refunds

Rules:
- Client code, API collections (Postman, Insomnia), tests and documentation are NOT entry points. An API specification (OpenAPI, GraphQL schema) is a registration only when the application routes requests from it (for example operationId wiring); then report the handler it points to.
- Cite only lines that exist in the provided code; the quote must be copied from that line (at most 80 characters).
- Use "unclear" or null instead of guessing. Omit what is not visible.
- Guards defined in another file still count if you can see where they are applied; report where they are applied.
- Keep the answer compact. No explanations.

Respond with JSON only:
{"entryPoints":[{"kind":"http","method":"PUT","path":"/notes/:id","file":"src/routes/notes.js","line":12,"quote":".put(validateToken, controller.update_note)","handler":{"file":"src/controllers/notes.js","startLine":40,"endLine":52,"name":"update_note"},"guards":[{"name":"validateToken","kind":"authn","scope":"route","order":"before","file":"src/routes/notes.js","line":12,"quote":".put(validateToken"}],"dataAccess":[{"resource":"Note","op":"write","filteredBy":"request-input","file":"src/controllers/notes.js","line":44,"quote":"Note.findOneAndUpdate({name: req.params.id}"}],"takesObjectId":true,"privileged":false,"public":false}],"ownership":[{"resource":"Note","file":"src/controllers/notes.js","line":30,"quote":"user: result.user"}],"traits":[{"trait":"money-arithmetic","file":"src/billing.js","startLine":10,"endLine":30,"quote":"function charge(amount)"}]}`;

export function mapUserContent(src: SourceFiles, batch: Array<{ file: string; start: number; end: number }>): string {
  const parts = batch.map((b) => {
    const lines = src.lines(b.file) ?? [];
    const range = b.start === 1 && b.end >= lines.length ? "" : ` (lines ${b.start}-${b.end})`;
    return `### ${b.file}${range}\n\`\`\`\n${src.numbered(b.file, b.start, b.end)}\n\`\`\``;
  });
  return `FILES (each line is prefixed with its number):\n\n${parts.join("\n\n")}`;
}

// ─── Verification ───────────────────────────────────────────────────────────

const ENTRY_KINDS = new Set<EntryKind>(["http", "graphql", "rpc", "webhook", "job", "consumer", "cron", "cli", "other"]);
const GUARD_KINDS = new Set<GuardKind>(["authn", "role", "owner", "other"]);
const FILTERS = new Set<Filter>(["caller-identity", "request-input", "both", "none", "unclear"]);
const str = (v: unknown, max = 200) => (typeof v === "string" ? v.slice(0, max) : "");
const int = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? Math.round(v) : typeof v === "string" && /^\d+$/.test(v) ? Number(v) : NaN);

interface Verifier { src: SourceFiles; known: Set<string>; discarded: number }

function loc(v: Verifier, raw: Record<string, unknown>): Loc | null {
  const file = resolveKnownFile(raw.file, v.known);
  const line = int(raw.line);
  const quote = str(raw.quote, 300);
  if (!file || !verifyQuote(v.src, file, line, quote)) {
    v.discarded++;
    return null;
  }
  return { file, line, quote };
}

function range(v: Verifier, raw: unknown): { file: string; startLine: number; endLine: number } | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const file = resolveKnownFile(r.file, v.known);
  const startLine = int(r.startLine);
  const endLine = int(r.endLine);
  const lines = file ? v.src.lines(file) : null;
  if (!file || !lines || !(startLine >= 1) || !(endLine >= startLine) || startLine > lines.length) {
    v.discarded++;
    return null;
  }
  return { file, startLine, endLine: Math.min(endLine, lines.length) };
}

/** Parse and verify one map answer. Facts whose lines don't check out are dropped. */
export function verifyMapAnswer(answer: unknown, src: SourceFiles, known: Set<string>): { entryPoints: EntryPoint[]; ownership: Ownership[]; traits: TraitRegion[]; reported: number; discarded: number } {
  const v: Verifier = { src, known, discarded: 0 };
  const a = (answer && typeof answer === "object" ? answer : {}) as Record<string, unknown>;
  const rawEntries = Array.isArray(a.entryPoints) ? a.entryPoints : [];
  const entryPoints: EntryPoint[] = [];
  for (const e of rawEntries) {
    if (!e || typeof e !== "object") continue;
    const r = e as Record<string, unknown>;
    const at = loc(v, r);
    if (!at) continue;
    const handlerRange = range(v, r.handler);
    const guards: Guard[] = [];
    for (const g of Array.isArray(r.guards) ? r.guards : []) {
      if (!g || typeof g !== "object") continue;
      const gr = g as Record<string, unknown>;
      const gl = loc(v, gr);
      if (!gl) continue;
      const kind = GUARD_KINDS.has(gr.kind as GuardKind) ? (gr.kind as GuardKind) : "other";
      const scope = ["route", "group", "global", "in-handler"].includes(gr.scope as string) ? (gr.scope as Guard["scope"]) : "route";
      const order = ["before", "after"].includes(gr.order as string) ? (gr.order as Guard["order"]) : "unclear";
      guards.push({ ...gl, name: str(gr.name, 80) || gl.quote.slice(0, 40), kind, scope, order });
    }
    const dataAccess: DataAccess[] = [];
    for (const d of Array.isArray(r.dataAccess) ? r.dataAccess : []) {
      if (!d || typeof d !== "object") continue;
      const dr = d as Record<string, unknown>;
      const dl = loc(v, dr);
      if (!dl) continue;
      const op = ["read", "write", "delete"].includes(dr.op as string) ? (dr.op as DataAccess["op"]) : "read";
      dataAccess.push({ ...dl, resource: str(dr.resource, 80), op, filteredBy: FILTERS.has(dr.filteredBy as Filter) ? (dr.filteredBy as Filter) : "unclear" });
    }
    const kind = ENTRY_KINDS.has(r.kind as EntryKind) ? (r.kind as EntryKind) : "other";
    const method = str(r.method, 40).toUpperCase() || "ANY";
    const p = str(r.path, 200);
    entryPoints.push({
      ...at,
      id: "",
      kind,
      method,
      path: p,
      handler: handlerRange ? { ...handlerRange, name: str((r.handler as Record<string, unknown>)?.name, 80) } : null,
      guards,
      dataAccess,
      takesObjectId: r.takesObjectId === true,
      privileged: r.privileged === true,
      public: r.public === true,
    });
  }
  const ownership: Ownership[] = [];
  for (const o of Array.isArray(a.ownership) ? a.ownership : []) {
    if (!o || typeof o !== "object") continue;
    const ol = loc(v, o as Record<string, unknown>);
    if (ol) ownership.push({ ...ol, resource: str((o as Record<string, unknown>).resource, 80) });
  }
  const traits: TraitRegion[] = [];
  for (const t of Array.isArray(a.traits) ? a.traits : []) {
    if (!t || typeof t !== "object") continue;
    const tr = t as Record<string, unknown>;
    if (!TRAITS.includes(tr.trait as Trait)) continue;
    const rg = range(v, tr);
    if (!rg) continue;
    const quote = str(tr.quote, 200);
    if (!verifyQuote(src, rg.file, rg.startLine, quote, 3)) {
      v.discarded++;
      continue;
    }
    traits.push({ trait: tr.trait as Trait, ...rg, endLine: Math.min(rg.endLine, rg.startLine + 200), quote });
  }
  return { entryPoints, ownership, traits, reported: rawEntries.length, discarded: v.discarded };
}

// ─── Merge ──────────────────────────────────────────────────────────────────

/** Path for comparison: lower case, no /api or version prefix, parameters unified. */
export function normalizePath(p: string): string {
  let out = (p || "").toLowerCase().split("?")[0].trim();
  out = out.replace(/\{[^}]*\}|<[^>]*>|:[\w-]+|\[[^\]]*\]|\*\w*/g, ":p");
  out = out.replace(/^\/?(?:api\/)?(?:v\d+\/)?/, "/").replace(/\/+$/, "");
  return out || "/";
}

/** Model or table name for comparison: lower case, no punctuation, singular. */
export function normalizeResource(r: string): string {
  const s = (r || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  return s.replace(/(?:ies)$/, "y").replace(/(?:ses|xes)$/, (m) => m.slice(0, -2)).replace(/s$/, "");
}

export function mergeEntryPoints(all: EntryPoint[]): EntryPoint[] {
  const byKey = new Map<string, EntryPoint>();
  for (const e of all) {
    const handlerKey = e.handler ? `${e.handler.file}:${e.handler.startLine}` : `${e.file}:${e.line}`;
    const key = `${e.method}|${normalizePath(e.path)}|${handlerKey}`;
    const prev = byKey.get(key);
    if (!prev) {
      byKey.set(key, { ...e });
      continue;
    }
    const seen = (l: Loc[], x: Loc) => l.some((y) => y.file === x.file && y.line === x.line);
    for (const g of e.guards) if (!seen(prev.guards, g)) prev.guards.push(g);
    for (const d of e.dataAccess) if (!seen(prev.dataAccess, d)) prev.dataAccess.push(d);
    prev.handler = prev.handler ?? e.handler;
    prev.takesObjectId ||= e.takesObjectId;
    prev.privileged ||= e.privileged;
    prev.public &&= e.public;
  }
  return [...byKey.values()].map((e, i) => ({ ...e, id: `E${i + 1}` }));
}
