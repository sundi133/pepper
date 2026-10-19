import { describe, expect, it, vi } from "vitest";
import { inflateRawSync } from "zlib";
import { anchorLine, reanchor, snippetLines } from "./anchor";
import { PepperApi, PepperApiError, checkServerUrl, scanPercent, type IdeFinding } from "./api";
import { countBySeverity, dedupeOnSave, findingDiagnostic, findingMarkdown, findingsForPath, indexByPath, lspSeverity, precommitDiagnostic } from "./diagnostics";
import { createZip, crc32 } from "./zip";

const finding = (over: Partial<IdeFinding> = {}): IdeFinding => ({
  id: "f1", severity: "HIGH", title: "[Zero-Day] SQL injection in search", description: "User input reaches a raw query.", filePath: "src/search.ts",
  startLine: 3, endLine: 3, ruleId: "r1", cveId: null, cweId: "CWE-89", scanner: "SAST_LLM", confidence: 0.9, status: "OPEN",
  snippet: "2: export function search(q: string) {\n3:   return db.query(\"SELECT * FROM t WHERE name = '\" + q + \"'\");\n4: }",
  riskScore: 80, remediation: "Use a parameterized query.", attackPath: "GET /search?q=' OR 1=1 --", validation: "confirmed", url: "https://pepper.example/scans/s1",
  ...over,
});

const DOC = ["import { db } from './db';", "export function search(q: string) {", "  return db.query(\"SELECT * FROM t WHERE name = '\" + q + \"'\");", "}"];

describe("re-anchoring", () => {
  it("strips line numbers from snippets and picks the line at the reported start", () => {
    expect(snippetLines("12: a\nb")).toEqual([{ text: "a", line: 12 }, { text: "b", line: null }]);
    expect(anchorLine(finding().snippet!, 3)?.text).toContain("db.query");
  });

  it("keeps a finding on its line when the code hasn't moved", () => {
    expect(reanchor(finding(), DOC)).toEqual({ start: 2, end: 2, exact: true });
  });

  it("follows the code when lines were added above it", () => {
    const moved = ["// new header", "// more", "", ...DOC];
    expect(reanchor(finding(), moved)).toEqual({ start: 5, end: 5, exact: true });
  });

  it("marks the finding as possibly outdated when its code is gone or ambiguous", () => {
    const gone = ["import { db } from './db';", "export const x = 1;", "", ""];
    expect(reanchor(finding(), gone)).toMatchObject({ start: 2, exact: false });
    // The same line two lines above and two below the reported line (3).
    const twice = [DOC[2], "", "", "", DOC[2]];
    expect(reanchor(finding(), twice)).toMatchObject({ start: 2, exact: false });
  });

  it("uses the reported line, clamped, for findings without a snippet", () => {
    expect(reanchor(finding({ snippet: null, startLine: 99, endLine: 99 }), DOC)).toEqual({ start: 3, end: 3, exact: true });
  });

  it("finds raw (unnumbered) snippets by their longest line", () => {
    const raw = finding({ snippet: "}\n  return db.query(\"SELECT * FROM t WHERE name = '\" + q + \"'\");\n" });
    expect(reanchor(raw, ["", "", ...DOC])).toMatchObject({ start: 4, exact: true });
  });
});

describe("diagnostics", () => {
  it("maps severities to LSP levels", () => {
    expect([lspSeverity("CRITICAL"), lspSeverity("HIGH"), lspSeverity("MEDIUM"), lspSeverity("LOW"), lspSeverity("INFO")]).toEqual([1, 1, 2, 3, 4]);
  });

  it("builds a diagnostic with the CWE, a link and the finding id, without the [Zero-Day] prefix", () => {
    const d = findingDiagnostic(finding(), DOC);
    expect(d).toMatchObject({ severity: 1, source: "Pepper", code: "CWE-89", codeDescription: { href: "https://pepper.example/scans/s1" }, data: { findingId: "f1" } });
    expect(d.message).toBe("SQL injection in search [HIGH]");
    expect(d.range.start).toEqual({ line: 2, character: 2 });
  });

  it("matches documents to finding paths, also under an extra leading folder", () => {
    const idx = indexByPath([finding(), finding({ id: "f2", filePath: "upload/src/other.ts" }), finding({ id: "f3", filePath: "app.jar!/com/x/A.java" })]);
    expect(findingsForPath(idx, "src/search.ts").map((f) => f.id)).toEqual(["f1"]);
    expect(findingsForPath(idx, "src\\other.ts").map((f) => f.id)).toEqual(["f2"]);
    expect([...idx.keys()]).not.toContain("app.jar!/com/x/A.java");
  });

  it("drops on-save results the scan already shows on the same line", () => {
    const scan = [findingDiagnostic(finding({ cweId: "CWE-798" }), DOC)];
    const same = precommitDiagnostic({ ruleId: "STRIPE", title: "Stripe key", description: "", severity: "CRITICAL", filePath: "src/search.ts", line: 3, snippet: "", category: "secret", cweId: "CWE-798" }, DOC);
    const other = precommitDiagnostic({ ruleId: "AWS", title: "AWS key", description: "", severity: "CRITICAL", filePath: "src/search.ts", line: 1, snippet: "", category: "secret", cweId: "CWE-798" }, DOC);
    expect(dedupeOnSave([same, other], scan)).toEqual([other]);
    expect(other.source).toBe("Pepper (on-save)");
  });

  it("renders hover markdown and counts", () => {
    const md = findingMarkdown(finding());
    expect(md).toContain("**Fix:** Use a parameterized query.");
    expect(md).toContain("[Open in Pepper](https://pepper.example/scans/s1)");
    expect(countBySeverity([finding(), finding({ severity: "LOW" })])).toMatchObject({ HIGH: 1, LOW: 1, CRITICAL: 0 });
  });
});

describe("API client", () => {
  const KEY = "pep_live_supersecretvalue123";
  const res = (status: number, body: unknown) => ({ status, ok: status < 300, json: async () => body, text: async () => JSON.stringify(body) });

  it("requires https except for localhost", () => {
    expect(checkServerUrl("https://sast.votal.ai/")).toBe("https://sast.votal.ai");
    expect(checkServerUrl("http://localhost:3300")).toBe("http://localhost:3300");
    expect(() => checkServerUrl("http://pepper.corp")).toThrow(/https/);
    expect(() => checkServerUrl("not a url")).toThrow(PepperApiError);
  });

  it("sends the key as a bearer token and builds the query", async () => {
    const f = vi.fn(async () => res(200, { scan: null, findings: [] }));
    await new PepperApi("https://p.example", KEY, f).findings("repo 1", "feat/x");
    const [url, init] = f.mock.calls[0] as unknown as [string, { headers: Record<string, string> }];
    expect(url).toBe("https://p.example/api/ide/findings?repositoryId=repo+1&branch=feat%2Fx");
    expect(init.headers.authorization).toBe(`Bearer ${KEY}`);
  });

  it("classifies errors and never puts the key in a message", async () => {
    const api = (status: number, body: unknown) => new PepperApi("https://p.example", KEY, async () => res(status, body));
    await expect(api(401, {}).findings("r", null)).rejects.toMatchObject({ kind: "auth" });
    await expect(api(403, { error: `key ${KEY} is a developer key` }).setStatus("f", "RESOLVED")).rejects.toMatchObject({ kind: "forbidden", message: expect.not.stringContaining(KEY) });
    await expect(api(404, { error: "Project not found" }).findings("r", null)).rejects.toMatchObject({ kind: "not-found" });
    await expect(api(502, {}).findings("r", null)).rejects.toMatchObject({ kind: "server" });
    const down = new PepperApi("https://p.example", KEY, async () => { throw new Error(`connect ECONNREFUSED (sent ${KEY})`); });
    const err = await down.findings("r", null).catch((e) => e as PepperApiError);
    expect(err.kind).toBe("network");
    expect(err.message).not.toContain(KEY);
    await expect(new PepperApi("https://p.example", "", async () => res(200, {})).findings("r", null)).rejects.toMatchObject({ kind: "auth" });
  });

  it("computes scan progress from per-scanner status", () => {
    expect(scanPercent({ id: "s", status: "RUNNING", scannerProgress: { A: { status: "DONE" }, B: { status: "RUNNING" } } })).toBe(50);
    expect(scanPercent({ id: "s", status: "QUEUED" })).toBe(0);
  });
});

describe("zip", () => {
  it("writes an archive whose entries inflate back to the input", () => {
    const files = [{ path: "src/a.ts", data: Buffer.from("export const a = 1;\n".repeat(50)) }, { path: "README.md", data: Buffer.from("x") }];
    const zip = Buffer.from(createZip(files));
    expect(zip.readUInt32LE(0)).toBe(0x04034b50);
    const eocd = zip.length - 22;
    expect(zip.readUInt32LE(eocd)).toBe(0x06054b50);
    expect(zip.readUInt16LE(eocd + 10)).toBe(2);
    // First entry: deflated, CRC matches.
    const nameLen = zip.readUInt16LE(26);
    const size = zip.readUInt32LE(18);
    const method = zip.readUInt16LE(8);
    const body = zip.subarray(30 + nameLen, 30 + nameLen + size);
    expect(zip.subarray(30, 30 + nameLen).toString()).toBe("src/a.ts");
    expect(method).toBe(8);
    expect(inflateRawSync(body).equals(files[0].data)).toBe(true);
    expect(zip.readUInt32LE(14)).toBe(crc32(files[0].data));
  });

  it("computes the standard CRC-32", () => {
    expect(crc32(Buffer.from("123456789")).toString(16)).toBe("cbf43926");
  });
});
