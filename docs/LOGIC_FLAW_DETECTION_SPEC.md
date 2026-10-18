# Logic-flaw detection: endpoint authorization map and incident patterns

Status: implemented behind settings (off by default); measurement (§6.2 runs C–E) pending.
Owner: Pepper scanning. Extends the zero-day scanner (`ZERO_DAY`) and is
measured with the harness in `docs/AI_SAST_ACCURACY_SPEC.md` (part A).

## 1. Problem

Authorization and business-logic flaws are the bugs behind most real security incidents.
They are also the product's core: pattern tools don't find them. Pepper already looks for
them in two places: the AI SAST pass (per file) and the zero-day scanner (cross-file). Both
have structural limits.

**0. The zero-day scanner dropped its own findings** (fixed in #156, v1.2.2). Its answer format never asked for `filePath`, yet the scanner
keeps only findings whose `filePath` is one of the files it sent. On VAmPI, Claude Sonnet
returned 7 correct findings, covering all 4 labelled authorization flaws, and all 7 were
dropped without a log line. The baseline run (section 6.2, A) shows 0 findings on every
app. The fix asks for the path, matches it to the sent files, and logs what it drops.

**1. The logic flaw spans files, but the model judges one view.** The classic breach is
`GET /orders/:id` checking that the order belongs to the caller while `PUT /orders/:id`
doesn't. The check lives in one handler, the gap in another, often in another file. AI SAST
sees one chunk at a time. The zero-day prompt tells the model to "only assert issues
supported by the current code chunk". Nothing ever compares the two endpoints.

**2. Coverage of the logic pass is capped and silent.** The zero-day scanner sends up to 96
files, chosen by file name, in **one** request, and has one answer of at most 8,192 tokens
for every finding in the repository:

| App | Source files | Files sent | Request size |
|---|---|---|---|
| vampi | 16 | 13 | ~14k tokens |
| dvws-node | 74 | 73 | ~58k tokens |
| rw-spring | 129 | 86 | ~46k tokens |
| pepper | ~7,200 | 94 | ~69k tokens |

On a real application, about 1% of the code is reviewed for logic, and nothing tells the user.

**3. The route map is a regex sample.** The repository context lists the first 40 routes
found by a few regexes. It finds none in the Java app (Spring `@GetMapping` isn't matched)
or the PHP app. It records no guards, middleware or data access per route. Real
applications register routes in many ways the regexes can't follow:

- Express route arguments with guards after the handler (dvws-node);
- Go wrapper chains such as `mw.AuthCheck(handler)` (govwa);
- OpenAPI `operationId` routing to Python functions (VAmPI);
- auth applied to a route group in another file (`v1.Use(AuthMiddleware(true))`, rw-go).

**4. Several incident classes are never asked about directly**, or only as one line in a
very long prompt:

- error paths and missing settings that **fail open**;
- webhooks, callbacks and retries that **process the same event twice**;
- **cache keys or module-level state shared across users or tenants**;
- **background jobs and consumers that skip the tenant or owner check** the API path has;
- **read-then-write races** on balances, stock, quotas and single-use codes;
- **money arithmetic**: floats for currency, negative or zero amounts, client-sent totals.

## 2. Goals

1. **Works on any code.** No list of supported languages or frameworks. The model reads
   the code and fills a fixed structure. Pepper verifies the structure against the source,
   and runs language-independent rules over it.
2. **Find cross-file authorization gaps** by comparing related entry points.
3. **Ask about the incident classes in 1.4 explicitly**, each with an exploit test and a
   defence test, on code regions selected for that class.
4. **Precision first.** A new finding needs a deterministic signal (an inconsistency in
   the verified map, or a verified trait) **and** AI confirmation with cited evidence that
   Pepper checks. Unconfirmed candidates are counted, not reported.
5. **Measured.** Ship on by default only if the harness shows higher recall on
   authorization and business-logic flaws with no more findings on safe or clean code
   (section 6).
6. **No regressions.** The existing zero-day pass and AI SAST are unchanged unless a
   measured change says otherwise. Each new pass can be switched off, and an error in a new
   pass never fails the scan.

Non-goals: runtime or exploit validation; audit-trail gaps (5.8, deferred).

## 3. Design overview

```
source files ──► map pass (AI, batched) ──► verified map ──► rules R1–R5 ──► confirm (AI) ──► findings
                     │                     (lines checked)                  ▲
                     └── traits ──► regions per pattern P1–P6 ──────────────┘
```

1. **Map pass (AI):** the model reads batches of files and reports entry points, their
   guards and data access, and **traits** of security-relevant functions. It reports
   facts with line numbers, never verdicts.
2. **Verification (deterministic):** every cited line must exist and contain the text the
   model quoted for it. Unverifiable facts are discarded.
3. **Rules (deterministic):** comparisons over the verified map yield candidates
   (section 4.3). Traits select regions for the incident patterns (section 5).
4. **Confirmation (AI):** each candidate or region gets a focused question with an exploit
   test and a defence test. Only confirmed answers with verified evidence become findings.

Splitting "what is in the code" (facts, checked against the source) from "is it a flaw"
(judged per candidate with only the relevant code) is what makes this generic and keeps
precision. The model never has to hold the whole application in mind at once.

## 4. Part 1: endpoint authorization map

### 4.1 Map pass

**File selection.** All source files are scored with language-independent hints and sent
in order, best first, until `LOGIC_MAP_MAX_FILES` (default 150) or the token budget:

- names such as route, controller, handler, view, api, resolver, endpoint, webhook, job,
  worker, consumer, task, middleware, auth, policy, permission;
- content with HTTP verbs next to path strings, decorators or annotations, `router`, `app.`,
  `@`, request or response parameters;
- files imported by already-selected files (their middleware and data access).

Files on the LLM exclusion list are never sent. Tests, fixtures and generated code are
skipped.

**Batches:** about 30k tokens of source per request, line-numbered. Each file is sent once.
A file larger than a batch is split on function boundaries where possible.

**Answer schema** (JSON; the model reports what is there, not what is wrong):

```ts
interface MapAnswer {
  entryPoints: Array<{
    kind: "http" | "graphql" | "rpc" | "webhook" | "job" | "consumer" | "cron" | "cli" | "other";
    method: string;            // GET, POST… or queue/job/command name
    path: string;              // as declared ("" when unknown)
    file: string; line: number; quote: string;           // the registration line and text
    handler: { file: string; startLine: number; endLine: number; name: string } | null;
    guards: Array<{ name: string; kind: "authn" | "role" | "owner" | "other";
                    file: string; line: number; quote: string; scope: "route" | "group" | "global" | "in-handler" }>;
    dataAccess: Array<{ file: string; line: number; quote: string; resource: string;
                        filteredBy: "caller-identity" | "request-input" | "both" | "none" | "unclear";
                        op: "read" | "write" | "delete" }>;
    takesObjectId: boolean;    // an id, name or key from the request selects the object
    privileged: boolean;       // admin, setup, reset, logs, config, user lists, exports
    public: boolean;           // meant for anonymous callers (login, register, health, docs)
  }>;
  ownership: Array<{ resource: string; file: string; line: number; quote: string }>;  // where an owner is recorded
  traits: Array<{ trait: Trait; file: string; startLine: number; endLine: number; quote: string }>;
}
type Trait = "security-check-error-path" | "external-event-side-effect" | "cache-or-shared-state"
           | "job-loads-by-payload-id" | "read-then-write-value" | "money-arithmetic";
```

`ownership` records where the app stores who owns a resource, for example
`new Note({ …, user: result.user })` or a `user_id` column. That is what lets R3 fire when
no sibling endpoint checks ownership.

The prompt defines each field with short examples from several stacks, and says to use
`unclear` or `null` rather than guess. It does not list frameworks to support.

### 4.2 Verification

For every `file:line` the model cites (registration, guards, data access, ownership,
traits), Pepper checks:

- the file is one that was sent;
- the line exists;
- the `quote` appears on that line (whitespace-insensitive), or within ±2 lines;
- for handlers, `startLine ≤ endLine` and the range lies inside the file.

A fact that fails is discarded. An entry point whose registration fails is discarded
whole. Counts go to the drop ledger, which measures how reliable the map is per model.

Entry points reported from several batches are merged by (method, normalized path,
handler location).

### 4.3 Rules (deterministic candidates)

Endpoints are grouped by **resource**: the normalized path (no `/api`, `/v1`, parameter
names unified), plus the `resource` names of their data access. They are also grouped by
**sibling set**: the same registration file or handler file.

| Rule | Candidate when | CWE |
|---|---|---|
| R1 missing authentication | Not public, no authn guard (at any scope), and a sibling or same-resource endpoint has one, or it is mutating or privileged while most entry points have one | CWE-306 / CWE-862 |
| R2 missing role check | Privileged, has authn, no role guard, and the app has role guards elsewhere, or its path is under admin | CWE-862 / CWE-285 |
| R3 missing ownership | Takes an object id, a data access is filtered by `request-input` only, and the resource is owned: a same-resource access is filtered by `caller-identity`, or an `ownership` record exists for it | CWE-639 |
| R4 guard after handler | A guard on the route whose line is after the handler's response, or a global guard registered after the routes it should cover | CWE-696 / CWE-862 |
| R5 job skips the API's check | A job or consumer accesses a resource by `request-input` (payload) when the API's entry points for that resource filter it by `caller-identity` | CWE-639 / CWE-862 |

Public entry points are excluded from R1 unless they are also privileged.

Candidates are ranked by:

1. mutating and privileged first, then reads;
2. rule order R4 > R1 > R3 > R2 > R5.

They are capped at `LOGIC_MAX_CANDIDATES` (default 40), and the cap is logged.

### 4.4 Confirmation

Candidates are sent in batches of up to 4. Each candidate carries:

- its map rows (the target and up to two references that have the control);
- the target handler and the references' guard and access lines, with line numbers;
- the code of the guards involved, when the map located them;
- every group- and global-scope guard line in the map.

The model answers `confirmed`, `rejected` or `unsure` per candidate, with:

- **Exploit test:** the request a different or lower-privileged user sends, and what they
  get.
- **Defence test:** look for a control the map missed: a group or global guard, a base
  class, a check in a helper the handler calls, or a framework default. If one exists, cite
  it and reject.
- **Evidence:** the reference line with the control, and the target line where it is
  missing. Pepper verifies both as in 4.2. A `confirmed` answer with unverifiable evidence
  is dropped and counted.

Only `confirmed` answers become findings. `unsure` and `rejected` go to the ledger.

### 4.5 Findings

These are `ZERO_DAY` findings, which needs no schema change, no UI change and keeps the
existing quality gates and the 0.72 floor.

- `ruleId`: `ZD-AUTHZ-R1` … `ZD-AUTHZ-R5`.
- **Title:** names both sides, e.g. "PUT /v2/notes/:noteId lets any user modify any note
  (notes record an owner, the lookup ignores it)".
- **Location:** the target handler, so that root-cause dedupe (same file, line bucket,
  weakness) merges it with the same flaw found by AI SAST or the main zero-day pass.
- **Metadata:** `route`, `method`, `references` (method, path, file:line), `rule`.

### 4.6 The map feeds the main zero-day pass

The main pass gets a compact table from the verified map in place of the "ROUTE MAP
(sample)":

- method, path, guards, filtering and file:line for each entry point;
- at most 120 rows.

This changes an existing pass, so it is measured on its own (6.2, run D).

## 5. Part 2: incident-pattern pack

The map pass's **traits** select code regions: the reported function range, verified as in
4.2. When the map pass didn't cover a file, a keyword prefilter adds regions. Its keywords
are deliberately language-neutral: catch/except/rescue near check or verify, webhook or
callback, cache or memo, balance, stock, quota, amount or price.

Each pattern is a small definition in `src/scanners/zero-day/patterns.ts`:

```ts
interface IncidentPattern {
  id: string;           // "fail-open"
  trait: Trait;
  cwe: string[];
  exploitTest: string;  // what an attacker does and gets
  defenceTest: string;  // what makes it safe: cite it and reject
  notFindings: string[];
}
```

Regions are deduplicated and capped (12 per pattern, `LOGIC_MAX_REGIONS` = 40 per scan).
They go to the model in batches of at most 6 regions (about 24k characters), with that
pattern's question only. A finding must cite lines inside its region, and Pepper verifies
them.

### 5.1 P1 Fail-open (`security-check-error-path`; CWE-636, CWE-280)

- **Exploit test:** the attacker makes the check throw (malformed token, unreachable
  dependency, oversized input) or relies on a missing setting, and the request is allowed.
- **Defence test:** the error path denies (401/403, rethrow, `next(err)`), or a missing
  setting stops startup.
- **Not findings:** log-and-rethrow; fallbacks in non-security features.

### 5.2 P2 Duplicate processing (`external-event-side-effect`; CWE-837, CWE-294)

- **Exploit test:** the same event delivered twice (provider retry or replay) applies the
  side effect twice: credit, refund, fulfilment, e-mail, balance.
- **Defence test:** an event-id or idempotency-key check, a unique constraint, or a
  "processed" status checked in the same transaction.
- **Not findings:** read-only handlers; naturally idempotent updates.

### 5.3 P3 Shared cache or state across users (`cache-or-shared-state`; CWE-524, CWE-488)

- **Exploit test:** user B receives data cached or stored for user A or tenant A.
- **Defence test:** the key includes the user or tenant, the data is the same for
  everyone, or the state is request-scoped.
- **Not findings:** caches of public or global data.

### 5.4 P4 Jobs without the API's check (`job-loads-by-payload-id`; CWE-639, CWE-862)

- **Exploit test:** a user who can enqueue (directly or through an API that forwards
  input) makes the job act on another user's or tenant's records.
- **Defence test:** the job re-scopes by the owner or tenant captured at enqueue, or the
  enqueuing API already constrained the id to the caller's records.

### 5.5 P5 Read-then-write races (`read-then-write-value`; CWE-362, CWE-367)

- **Exploit test:** two concurrent requests both pass the check and both apply the change
  (double spend, oversell, coupon reuse).
- **Defence test:** row locking in a transaction, an atomic conditional update, an
  optimistic version check, or a unique constraint.
- **Not findings:** values that aren't security- or money-relevant.

### 5.6 P6 Money arithmetic (`money-arithmetic`; CWE-1339, CWE-681, CWE-1284)

- **Exploit test:** a negative or zero amount reverses a transfer or refund; a
  client-sent total or unit price is trusted; repeated rounding gains value.
- **Defence test:** integer minor units or a decimal type; positive-amount validation;
  totals recomputed server-side.
- **Not findings:** floats used only for display or analytics.

### 5.7 Relation to the main prompt

The zero-day prompt keeps its list of races, cache leakage and rollback. The pack adds a
focused pass on selected regions. If the harness shows the pack supersedes parts of the
list, those parts are shortened later, as a separate measured change.

### 5.8 Considered and deferred: audit-trail gaps (CWE-778)

A privileged action without an audit log matters in incidents, but the check is noisy and
the gap isn't exploitable by itself. If added later, it would be consistency-only and LOW:
the app logs other privileged mutations, and this one doesn't.

## 6. Measurement

### 6.1 Corpus and fixture

- **Existing corpus:** 5 vulnerable apps with 25 labelled authorization and 2
  business-logic flaws (many of them sibling inconsistencies: dvws-node's `sysinfo` and
  `admin/logs`, govwa's `/setup`, vampi's password change), plus 3 clean RealWorld apps
  for false positives. The apps cover Node, Python, Go, PHP and Java with five different
  routing styles, which is the generality test.
- **New fixture `eval/fixtures/logic-lab`:** two small apps (Express/TypeScript and Flask).
  Each contains every rule (R1–R5) and pattern (P1–P6) in a **vulnerable** form and a
  **safe twin**. They are labelled in `eval/truth/logic-lab.json`: the vulnerable forms as
  `expected`, the safe twins as `must_not_report`. The corpus format gains a `path` field
  for local fixtures. The fixture tests mechanics; the real apps decide what ships.

### 6.2 Runs

Each run is `ZERO_DAY_ONLY`, 2 runs per app, with the same model:

- **A:** the code before the file-path fix (recorded: 0 findings everywhere).
- **B:** A with the file-path fix: the true baseline for the new work.
- **C:** B with the map and rules R1–R5 (Part 1).
- **D:** C with the map table in the main pass (4.6).
- **E:** D with the pattern pack (Part 2).

A final full AI run (`SAST_ONLY` plus `ZERO_DAY_ONLY`) checks the net effect after
cross-scanner dedupe.

### 6.3 Drop ledger

Each pass logs its counts, and the harness reports them:

- map facts verified and discarded;
- entry points per kind;
- candidates per rule and regions per pattern;
- confirmed, rejected and unsure;
- dropped by evidence verification;
- dropped by the caps.

### 6.4 Gates to ship on by default

1. **Recall:** authorization plus business-logic recall on the real corpus rises by at
   least 10 points (absolute) from B.
2. **Safe code:** no more safe-code hits than B, on the corpus and on the fixture's safe
   twins.
3. **Clean apps:** at most 2 more unlabelled findings per clean app, each reviewed by hand.
4. **Each part on its own:** each of C, D and E must not lower recall or precision
   compared with the previous run, or that part ships off by default.
5. **Tests:** the full vitest suite passes, and the existing zero-day tests pass unchanged.

Results go to `eval/results/logic-*` and are summarised in the PR.

## 7. Settings, cost and rollout

| Setting | Default | Purpose |
|---|---|---|
| `LOGIC_ENDPOINT_MAP` | `false` (`true` once gates pass) | Part 1 |
| `LOGIC_PATTERN_PACK` | `false` (`true` once gates pass) | Part 2 |
| `LOGIC_MAP_IN_PROMPT` | `false` (`true` once gates pass) | map table in the main pass (4.6) |
| `LOGIC_MAP_MAX_FILES` | 150 | files the map pass reads per scan |
| `LOGIC_MAX_CANDIDATES` | 40 | Part 1 candidates per scan |
| `LOGIC_MAX_REGIONS` | 40 | Part 2 regions per scan |
| `LOGIC_CONCURRENCY` | 3 | concurrent AI requests of the logic passes |

- **Cost per scan:**
  - map: source up to the file cap, in about 30k-token batches (≈ 5 calls for a typical
    service);
  - confirmation: at most 10 calls;
  - patterns: at most 8 calls.

  Each confirmation and pattern call is a few thousand tokens. That is comparable to AI
  SAST on the same files. Calls run at concurrency 3 and respect stop/cancel.
- **Coverage is reported:** when the map pass reads fewer than all source files, the scan's
  progress log says "Logic review covered N of M source files".
- **Providers:** short JSON prompts that work on Ollama and non-reasoning models. The
  truncated-answer recovery applies.
- **Failure:** any error in a new pass is logged and that pass returns nothing. The main
  zero-day pass and the scan continue.
- **Rollout:** behind the settings, measured, then on by default in a minor release.

## 8. Open questions

- **Map reliability per model.** The ledger shows how many facts each model gets wrong.
  If a provider's map is too noisy, the passes can stay off for it.
- **A deterministic extractor as a cross-check:** for very common frameworks (Express,
  Spring, Flask), regexes could confirm or add entry points cheaply. Add one only if the
  ledger shows the map missing entry points there.
- **Showing the map to users** (scan page or report) as an attack-surface inventory. Out
  of scope here.
