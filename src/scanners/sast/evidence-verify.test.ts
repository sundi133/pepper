import { describe, it, expect } from "vitest";
import {
  anchorFindingToEvidence,
  extractEvidenceAnchors,
  isAuthorizationOrLogicFinding,
  verifyFindingEvidence,
} from "./evidence-verify";

const FILE = [
  "const express = require('express');",
  "const app = express();",
  "app.get('/users/:id', (req, res) => {",
  "  const userId = req.params.id;",
  "  const query = 'SELECT * FROM users WHERE id = ' + userId;",
  "  db.query(query);",
  "});",
].join("\n");

describe("extractEvidenceAnchors", () => {
  it("extracts identifiers from sink and parameter fields", () => {
    const anchors = extractEvidenceAnchors({
      metadata: { sink: "db.query", parameter: "userId" },
    });
    expect(anchors).toContain("query");
    expect(anchors).toContain("userId");
    // Two-character namespace prefixes are too short to be evidence anchors.
    expect(anchors).not.toContain("db");
  });

  it("drops generic stop words and short tokens", () => {
    const anchors = extractEvidenceAnchors({
      metadata: { sink: "the query into an object", parameter: "id" },
    });
    expect(anchors).not.toContain("the");
    expect(anchors).not.toContain("object");
    expect(anchors).not.toContain("id"); // length < 3
    expect(anchors).toContain("query");
  });

  it("handles null/absent metadata", () => {
    expect(extractEvidenceAnchors({ metadata: { sink: "null" } })).toEqual([]);
    expect(extractEvidenceAnchors({})).toEqual([]);
  });
});

describe("verifyFindingEvidence", () => {
  it("passes when it cannot verify (no file content)", () => {
    const v = verifyFindingEvidence(
      { startLine: 1, metadata: { sink: "madeUpSink" } },
      undefined,
    );
    expect(v.ok).toBe(true);
  });

  it("passes when no identifiers were cited", () => {
    const v = verifyFindingEvidence({ startLine: 1, metadata: {} }, FILE);
    expect(v.ok).toBe(true);
  });

  it("passes when the cited sink exists in the file", () => {
    const v = verifyFindingEvidence(
      { startLine: 5, metadata: { sink: "db.query", parameter: "userId" } },
      FILE,
    );
    expect(v.ok).toBe(true);
    expect(v.matched).toContain("query");
  });

  it("drops a finding whose cited identifiers are entirely absent", () => {
    const v = verifyFindingEvidence(
      { startLine: 5, metadata: { sink: "unsafeEval", parameter: "userInputValue" } },
      FILE,
    );
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/none of the cited/);
  });

  it("drops a finding citing a line past the end of the file", () => {
    const v = verifyFindingEvidence(
      { startLine: 9999, metadata: { sink: "db.query" } },
      FILE,
    );
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/outside the .* file/);
  });

  it("passes when only one of several cited identifiers exists", () => {
    const v = verifyFindingEvidence(
      { startLine: 5, metadata: { sink: "db.query", parameter: "notHereAtAll" } },
      FILE,
    );
    expect(v.ok).toBe(true);
  });
});

describe("authorization and business-logic findings are never dropped for their wording", () => {
  const ORDERS = [
    "router.get('/orders/:id', requireLogin, async (req, res) => {",
    "  const order = await Order.findById(req.params.id);",
    "  res.json(order);",
    "});",
    "router.post('/checkout', async (req, res) => {",
    "  const total = req.body.price * req.body.quantity;",
    "  await charge(req.user, total);",
    "});",
  ].join("\n");

  it("keeps an IDOR whose sink is described in words", () => {
    const f = {
      title: "IDOR: any logged-in user can read another user's order",
      cweId: "CWE-639",
      startLine: 2,
      metadata: { sink: "missing ownership verification", parameter: "orderIdentifier" },
    };
    expect(verifyFindingEvidence(f, ORDERS).ok).toBe(true);
  });

  it("keeps missing-authorization, business-logic and race findings recognised by title or weakness class", () => {
    for (const f of [
      { title: "Missing authorization on admin export route", metadata: { sink: "AdminGuard absent" } },
      { title: "Business logic flaw: client-controlled price at checkout", metadata: { sink: "priceCalculation" } },
      { title: "Race condition allows double spend of wallet balance", metadata: { sink: "balanceDeduction" } },
      { title: "Order total trusts request body", metadata: { weaknessClass: "Business Logic", sink: "totalComputation" } },
      { title: "Coupon reuse", cweId: "CWE-841", metadata: { sink: "couponRedemptionFlow" } },
      { title: "Authentication bypass via role header", metadata: { sink: "roleHeaderTrust" } },
    ]) {
      expect(isAuthorizationOrLogicFinding(f), f.title).toBe(true);
      expect(verifyFindingEvidence({ ...f, startLine: 5 }, ORDERS).ok, f.title).toBe(true);
    }
  });

  it("still drops one that points past the end of the file", () => {
    const f = { title: "IDOR on orders", cweId: "CWE-639", startLine: 400, metadata: { sink: "Order.findById" } };
    expect(verifyFindingEvidence(f, ORDERS).ok).toBe(false);
  });

  it("still drops an injection finding citing names that are not in the file", () => {
    const f = { title: "SQL injection", cweId: "CWE-89", startLine: 2, metadata: { sink: "rawQueryExecutor", parameter: "userInputValue" } };
    expect(isAuthorizationOrLogicFinding(f)).toBe(false);
    expect(verifyFindingEvidence(f, ORDERS).ok).toBe(false);
  });

  it("does not treat ordinary injection or crypto findings as logic findings", () => {
    for (const f of [
      { title: "Command injection via exec", cweId: "CWE-78" },
      { title: "Weak hash for passwords", cweId: "CWE-328" },
      { title: "Path traversal in download", cweId: "CWE-22" },
    ]) {
      expect(isAuthorizationOrLogicFinding(f), f.title).toBe(false);
    }
  });
});

describe("anchorFindingToEvidence", () => {
  const sqli = { title: "SQL injection", cweId: "CWE-89", metadata: { sink: "db.query", parameter: "userId" } };

  it("keeps a finding whose cited lines hold the evidence", () => {
    const a = anchorFindingToEvidence({ ...sqli, startLine: 6, endLine: 6 }, FILE, { startLine: 1, endLine: 7 });
    expect(a).toMatchObject({ ok: true, startLine: 6, endLine: 6 });
    expect(a.relocated).toBeUndefined();
  });

  it("moves a wrong line number to the nearest line holding the cited sink", () => {
    const long = [FILE, ...Array.from({ length: 20 }, (_, i) => `// filler ${i}`)].join("\n");
    const a = anchorFindingToEvidence({ ...sqli, startLine: 20, endLine: 21 }, long, { startLine: 1, endLine: 27 });
    expect(a.ok).toBe(true);
    expect(a.relocated).toBe(true);
    expect(a.startLine).toBe(6);
    expect(a.endLine).toBe(7);
  });

  it("rejects a finding whose evidence is outside the lines the model was shown", () => {
    const a = anchorFindingToEvidence({ ...sqli, startLine: 2 }, FILE, { startLine: 1, endLine: 3 });
    expect(a.ok).toBe(false);
    expect(a.reason).toMatch(/reviewed lines 1-3/);
  });

  it("matches whole identifiers, not substrings", () => {
    const file = "const querySelectorAll = 1;\nconst x = 2;\nconst y = 3;\nconst z = 4;\nrun();";
    const a = anchorFindingToEvidence({ title: "Injection", metadata: { sink: "query" }, startLine: 5 }, file);
    expect(a.ok).toBe(false);
  });

  it("rejects a citation outside the reviewed lines when nothing can be checked", () => {
    expect(anchorFindingToEvidence({ title: "Weak crypto", startLine: 90, metadata: {} }, FILE, { startLine: 1, endLine: 7 }).ok).toBe(false);
    expect(anchorFindingToEvidence({ title: "Weak crypto", startLine: 9, metadata: {} }, FILE, { startLine: 1, endLine: 7 }).ok).toBe(true);
  });

  it("never moves or rejects authorization and business-logic findings", () => {
    const idor = { title: "IDOR on order lookup", cweId: "CWE-639", startLine: 2, metadata: { sink: "findOrder" } };
    expect(anchorFindingToEvidence(idor, FILE, { startLine: 1, endLine: 3 })).toMatchObject({ ok: true, startLine: 2 });
  });
});
