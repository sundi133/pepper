import { describe, expect, it, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const answers = vi.fn();
vi.mock("@/lib/llm-gateway", async (orig) => ({
  ...(await orig<typeof import("@/lib/llm-gateway")>()),
  analyzeWithLlm: (_c: unknown, _m: unknown, system: string, user: string) => answers(system, user),
}));

import { SourceFiles, verifyQuote } from "./source";
import { normalizePath, normalizeResource, verifyMapAnswer, mergeEntryPoints, selectMapFiles, type EntryPoint } from "./map";
import { findCandidates } from "./rules";
import { findingsFromConfirmation } from "./confirm";
import { findingsFromPatternAnswer, selectRegions, PATTERNS } from "./patterns";
import { runLogicPasses, endpointTable } from "./index";

// A small app in the shape of a real one: routes in one file, handlers in another.
const FILES: Record<string, string> = {
  "src/routes/notes.js": [
    "const c = require('../controllers/notes');", // 1
    "const auth = require('../middleware/auth').validateToken;", // 2
    "module.exports = (router) => {", // 3
    "  router.route('/v2/notes').post(auth, c.create);", // 4
    "  router.route('/v2/notes/:id').get(auth, c.read);", // 5
    "  router.route('/v2/notes/:id').put(auth, c.update);", // 6
    "  router.route('/v2/admin/logs').get(auth, c.logs);", // 7
    "  router.route('/v2/export').get(c.exportAll);", // 8
    "  router.route('/v2/users').get(auth, requireAdmin, c.users);", // 9
    "};", // 10
  ].join("\n"),
  "src/controllers/notes.js": [
    "module.exports = {", // 1
    "  create: async (req, res) => {", // 2
    "    const note = new Note({ body: req.body.body, user: req.user.id });", // 3
    "    res.json(await note.save());", // 4
    "  },", // 5
    "  read: async (req, res) => {", // 6
    "    res.json(await Note.findOne({ _id: req.params.id, user: req.user.id }));", // 7
    "  },", // 8
    "  update: async (req, res) => {", // 9
    "    res.json(await Note.findOneAndUpdate({ _id: req.params.id }, req.body));", // 10
    "  },", // 11
    "  logs: async (req, res) => res.json(await Log.find({})),", // 12
    "  exportAll: async (req, res) => res.json(await Note.find({})),", // 13
    "  users: async (req, res) => res.json(await User.find({})),", // 14
    "};", // 15
  ].join("\n"),
};

function repo(files = FILES): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-logic-"));
  for (const [rel, content] of Object.entries(files)) {
    fs.mkdirSync(path.join(root, path.dirname(rel)), { recursive: true });
    fs.writeFileSync(path.join(root, rel), content);
  }
  return root;
}

const R = "src/routes/notes.js";
const C = "src/controllers/notes.js";
const g = (line: number, quote: string, kind = "authn", name = "auth") => ({ name, kind, scope: "route", order: "before", file: R, line, quote });
const ep = (method: string, p: string, line: number, quote: string, handler: [number, number, string], guards: unknown[], access: unknown[], extra: Record<string, unknown> = {}) => ({
  kind: "http", method, path: p, file: R, line, quote, handler: { file: C, startLine: handler[0], endLine: handler[1], name: handler[2] }, guards, dataAccess: access, takesObjectId: false, privileged: false, public: false, ...extra,
});

/** What a model would report for FILES (facts only, with quotes). */
const MAP_ANSWER = {
  entryPoints: [
    ep("POST", "/v2/notes", 4, ".post(auth, c.create)", [2, 5, "create"], [g(4, ".post(auth")], [{ resource: "Note", op: "write", filteredBy: "caller-identity", file: C, line: 3, quote: "new Note({ body: req.body.body, user: req.user.id })" }]),
    ep("GET", "/v2/notes/:id", 5, ".get(auth, c.read)", [6, 8, "read"], [g(5, ".get(auth")], [{ resource: "Note", op: "read", filteredBy: "both", file: C, line: 7, quote: "Note.findOne({ _id: req.params.id, user: req.user.id })" }], { takesObjectId: true }),
    ep("PUT", "/v2/notes/:id", 6, ".put(auth, c.update)", [9, 11, "update"], [g(6, ".put(auth")], [{ resource: "Note", op: "write", filteredBy: "request-input", file: C, line: 10, quote: "Note.findOneAndUpdate({ _id: req.params.id }, req.body)" }], { takesObjectId: true }),
    ep("GET", "/v2/admin/logs", 7, ".get(auth, c.logs)", [12, 12, "logs"], [g(7, ".get(auth")], [{ resource: "Log", op: "read", filteredBy: "none", file: C, line: 12, quote: "Log.find({})" }], { privileged: true }),
    ep("GET", "/v2/export", 8, ".get(c.exportAll)", [13, 13, "exportAll"], [], [{ resource: "Note", op: "read", filteredBy: "none", file: C, line: 13, quote: "Note.find({})" }], { privileged: true }),
    ep("GET", "/v2/users", 9, "requireAdmin, c.users", [14, 14, "users"], [g(9, ".get(auth"), g(9, "requireAdmin", "role", "requireAdmin")], [{ resource: "User", op: "read", filteredBy: "none", file: C, line: 14, quote: "User.find({})" }], { privileged: true }),
    // Made-up facts are discarded:
    ep("DELETE", "/v2/notes/:id", 99, "router.delete('/v2/notes/:id')", [9, 11, "remove"], [], []),
  ],
  ownership: [{ resource: "Note", file: C, line: 3, quote: "user: req.user.id" }],
  traits: [{ trait: "money-arithmetic", file: C, startLine: 2, endLine: 5, quote: "this line does not exist" }],
};

describe("source and map verification", () => {
  it("accepts a quote on the cited line or within two lines, and rejects made-up ones", () => {
    const root = repo();
    const src = new SourceFiles(root);
    expect(verifyQuote(src, C, 10, "Note.findOneAndUpdate({ _id: req.params.id }")).toBe(true);
    expect(verifyQuote(src, C, 9, "findOneAndUpdate")).toBe(true);
    expect(verifyQuote(src, C, 3, "Note.deleteMany")).toBe(false);
    expect(verifyQuote(src, C, 3, "  ")).toBe(false);
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("keeps verified facts and discards the rest", () => {
    const root = repo();
    const src = new SourceFiles(root);
    const v = verifyMapAnswer(MAP_ANSWER, src, new Set([R, C]));
    expect(v.reported).toBe(7);
    expect(v.entryPoints).toHaveLength(6);
    expect(v.ownership).toHaveLength(1);
    expect(v.traits).toHaveLength(0);
    expect(v.discarded).toBeGreaterThanOrEqual(2);
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("normalizes paths and resource names across styles", () => {
    expect(normalizePath("/api/v1/orders/{orderId}/")).toBe("/orders/:p");
    expect(normalizePath("/orders/<int:id>")).toBe("/orders/:p");
    expect(normalizePath("/v2/notes/:noteId")).toBe("/notes/:p");
    expect(normalizeResource("Notes")).toBe(normalizeResource("note"));
    expect(normalizeResource("categories")).toBe("category");
  });

  it("ranks files that look like entry points first and skips tests", () => {
    const root = repo({ ...FILES, "src/util/strings.js": "module.exports = (s) => s.trim();", "test/notes.test.js": "it('x', () => {})" });
    const src = new SourceFiles(root);
    const { selected, sourceCount } = selectMapFiles(src, [...Object.keys(FILES), "src/util/strings.js", "test/notes.test.js"], 10);
    expect(sourceCount).toBe(3);
    expect(selected.slice(0, 2).sort()).toEqual([C, R].sort());
    fs.rmSync(root, { recursive: true, force: true });
  });
});

function entries(): EntryPoint[] {
  const root = repo();
  const v = verifyMapAnswer(MAP_ANSWER, new SourceFiles(root), new Set([R, C]));
  fs.rmSync(root, { recursive: true, force: true });
  return mergeEntryPoints(v.entryPoints);
}

describe("rules", () => {
  it("finds the missing ownership check, the privileged endpoint behind login only, and the unauthenticated export", () => {
    const e = entries();
    const { candidates, byRule } = findCandidates({ entryPoints: e, ownership: [{ resource: "Note", file: C, line: 3, quote: "user: req.user.id" }] }, 40);
    const by = (rule: string) => candidates.filter((c) => c.rule === rule).map((c) => `${c.target.method} ${c.target.path}`);
    expect(by("R3")).toEqual(["PUT /v2/notes/:id"]);
    expect(by("R2")).toEqual(["GET /v2/admin/logs"]);
    expect(by("R1")).toEqual(["GET /v2/export"]);
    // The read that is scoped by the caller and the admin route with a role check are not candidates.
    expect(candidates.some((c) => c.target.path === "/v2/users")).toBe(false);
    expect(candidates.some((c) => c.target.method === "GET" && c.target.path === "/v2/notes/:id")).toBe(false);
    expect(byRule.R4).toBe(0);
  });

  it("flags a guard registered after the handler", () => {
    const e = entries();
    e[1].guards = [{ ...e[1].guards[0], name: "guard.check", kind: "role", order: "after" }];
    const { candidates } = findCandidates({ entryPoints: e, ownership: [] }, 40);
    expect(candidates.find((c) => c.rule === "R4")?.target.path).toBe("/v2/notes/:id");
  });

  it("caps candidates and puts mutating ones first", () => {
    const { candidates, capped } = findCandidates({ entryPoints: entries(), ownership: [{ resource: "Note", file: C, line: 3, quote: "user: req.user.id" }] }, 1);
    expect(candidates).toHaveLength(1);
    expect(capped).toBe(2);
    expect(candidates[0].target.method).toBe("PUT");
  });
});

describe("confirmation evidence", () => {
  const setup = () => {
    const root = repo();
    const src = new SourceFiles(root);
    const { candidates } = findCandidates({ entryPoints: entries(), ownership: [{ resource: "Note", file: C, line: 3, quote: "user: req.user.id" }] }, 40);
    const c = candidates.find((x) => x.rule === "R3")!;
    return { root, src, c };
  };
  const confirmed = (target: Record<string, unknown>, reference: Record<string, unknown>) => ({
    results: [{ id: "", verdict: "confirmed", confidence: 0.9, severity: "HIGH", title: "PUT /v2/notes/:id lets any user change any note", description: "d", exploit: "PUT /v2/notes/<victim note id> with the attacker's token", defence: "looked for an owner filter", recommendation: "filter by req.user.id", evidence: { target, reference } }],
  });

  it("turns a confirmed answer with verified evidence into a finding at the target", () => {
    const { root, src, c } = setup();
    const a = confirmed({ file: C, line: 10, quote: "Note.findOneAndUpdate({ _id: req.params.id }" }, { file: C, line: 3, quote: "user: req.user.id" });
    a.results[0].id = c.id;
    const out = findingsFromConfirmation(a, [c], src, new Set([R, C]));
    expect(out.confirmed).toBe(1);
    expect(out.findings[0]).toMatchObject({ scanner: "ZERO_DAY", filePath: C, startLine: 10, cweId: "CWE-639", ruleId: "ZD-AUTHZ-R3" });
    expect(out.findings[0].metadata).toMatchObject({ route: "/v2/notes/:id", method: "PUT" });
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("drops a confirmation whose evidence is outside the target or made up", () => {
    const { root, src, c } = setup();
    const outside = confirmed({ file: C, line: 13, quote: "Note.find({})" }, { file: C, line: 3, quote: "user: req.user.id" });
    outside.results[0].id = c.id;
    const madeUp = confirmed({ file: C, line: 10, quote: "Note.findOneAndUpdate({ _id: req.params.id }" }, { file: C, line: 3, quote: "ownerCheck(req.user)" });
    madeUp.results[0].id = c.id;
    expect(findingsFromConfirmation(outside, [c], src, new Set([R, C])).evidenceFailed).toBe(1);
    expect(findingsFromConfirmation(madeUp, [c], src, new Set([R, C])).evidenceFailed).toBe(1);
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("counts rejected and unanswered candidates without reporting them", () => {
    const { root, src, c } = setup();
    const out = findingsFromConfirmation({ results: [{ id: c.id, verdict: "rejected" }] }, [c], src, new Set([R, C]));
    expect(out).toMatchObject({ rejected: 1, confirmed: 0, findings: [] });
    expect(findingsFromConfirmation({}, [c], src, new Set([R, C])).unsure).toBe(1);
    fs.rmSync(root, { recursive: true, force: true });
  });
});

describe("pattern pack", () => {
  const PAY = "src/payments/webhook.js";
  const files = {
    [PAY]: [
      "router.post('/webhooks/stripe', async (req, res) => {", // 1
      "  const event = req.body;", // 2
      "  if (event.type === 'payment.succeeded') {", // 3
      "    const user = await User.findById(event.data.userId);", // 4
      "    user.credits += event.data.amount;", // 5
      "    await user.save();", // 6
      "  }", // 7
      "  res.sendStatus(200);", // 8
      "});", // 9
    ].join("\n"),
  };

  it("selects regions from traits and from keywords in files the map did not read", () => {
    const root = repo(files);
    const src = new SourceFiles(root);
    const fromTrait = selectRegions(src, [{ trait: "external-event-side-effect", file: PAY, startLine: 1, endLine: 9, quote: "router.post" }], [], 12, 40);
    expect(fromTrait.map((r) => r.pattern.id)).toEqual(["P2"]);
    const fromKeywords = selectRegions(src, [], [PAY], 12, 40);
    expect(fromKeywords.map((r) => r.pattern.id)).toContain("P2");
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("keeps a verified finding inside the region and drops evidence outside it", () => {
    const root = repo(files);
    const src = new SourceFiles(root);
    const region = { id: "R1", pattern: PATTERNS.find((p) => p.id === "P2")!, file: PAY, startLine: 1, endLine: 9 };
    const ok = { region: "R1", title: "Stripe webhook credits twice on retry", severity: "HIGH", confidence: 0.88, file: PAY, line: 5, quote: "user.credits += event.data.amount;", description: "d", exploit: "replay", recommendation: "store event ids" };
    const out = findingsFromPatternAnswer({ findings: [ok, { ...ok, line: 40 }, { ...ok, confidence: 0.6 }] }, [region], src, new Set([PAY]), 0.72);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({ filePath: PAY, startLine: 5, cweId: "CWE-837", ruleId: "ZD-PATTERN-P2" });
    expect(out.evidenceFailed).toBe(1);
    expect(out.lowConfidence).toBe(1);
    fs.rmSync(root, { recursive: true, force: true });
  });
});

describe("runLogicPasses with a scripted model", () => {
  it("maps, compares, confirms, and reports only what verifies", async () => {
    const root = repo();
    answers.mockImplementation(async (system: string, user: string) => {
      if (system.startsWith("You map")) return JSON.stringify(MAP_ANSWER);
      if (system.includes("CANDIDATE authorization gaps")) {
        const ids = [...user.matchAll(/CANDIDATE (C\d+) — (R\d)/g)].map((m) => ({ id: m[1], rule: m[2] }));
        return JSON.stringify({
          results: ids.map(({ id, rule }) =>
            rule === "R3"
              ? { id, verdict: "confirmed", confidence: 0.9, severity: "HIGH", title: "PUT /v2/notes/:id lets any user change any note", description: "d", exploit: "e", recommendation: "r", evidence: { target: { file: C, line: 10, quote: "Note.findOneAndUpdate" }, reference: { file: C, line: 3, quote: "user: req.user.id" } } }
              : { id, verdict: "rejected" },
          ),
        });
      }
      return JSON.stringify({ findings: [] });
    });
    const out = await runLogicPasses({
      workDir: root, fileList: [R, C], client: { type: "openai", client: {}, model: "m" } as never, model: "m", maxResponseTokens: 4096,
      endpointMap: true, patternPack: true, maxMapFiles: 150, maxCandidates: 40, maxRegions: 40, concurrency: 2, minConfidence: 0.72,
    });
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({ ruleId: "ZD-AUTHZ-R3", filePath: C, startLine: 10 });
    expect(out.ledger).toMatchObject({ entryPoints: 6, candidates: 3, confirmed: 1, rejected: 2 });
    expect(endpointTable(out.map!)).toContain("PUT /v2/notes/:id | guards: auth(authn) | data: Note:request-input");
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("returns nothing, without throwing, when the model fails", async () => {
    const root = repo();
    answers.mockRejectedValue(new Error("402 insufficient credits"));
    const out = await runLogicPasses({
      workDir: root, fileList: [R, C], client: {} as never, model: "m", maxResponseTokens: 4096,
      endpointMap: true, patternPack: true, maxMapFiles: 150, maxCandidates: 40, maxRegions: 40, concurrency: 2, minConfidence: 0.72,
    });
    expect(out.findings).toEqual([]);
    expect(out.ledger.callsFailed).toBeGreaterThan(0);
    fs.rmSync(root, { recursive: true, force: true });
  });
});
