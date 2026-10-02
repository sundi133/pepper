import { describe, it, expect } from "vitest";
import {
  extractEvidenceAnchors,
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
