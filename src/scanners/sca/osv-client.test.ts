import { afterEach, describe, expect, it, vi } from "vitest";
import { queryOsvBatch } from "./osv-client";

const FULL_RECORD = {
  id: "GHSA-35jh-r3h4-6jhm",
  summary: "Command Injection in lodash",
  details: "lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
  aliases: ["CVE-2021-23337"],
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
  affected: [
    {
      package: { name: "lodash", ecosystem: "npm" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
    },
  ],
  database_specific: { cwe_ids: ["CWE-77", "CWE-94"], severity: "HIGH" },
};

type Handler = (url: string, body: unknown) => { status: number; json: unknown };

function mockOsv(handler: Handler) {
  const calls: Array<{ url: string; body: unknown }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ url: String(url), body });
      const r = handler(String(url), body);
      return new Response(JSON.stringify(r.json), { status: r.status });
    }),
  );
  return calls;
}

afterEach(() => vi.unstubAllGlobals());

describe("queryOsvBatch", () => {
  it("hydrates id-only batch results into full findings (severity, CVE, fix, CWE)", async () => {
    const calls = mockOsv((url) =>
      url.endsWith("/v1/querybatch")
        ? { status: 200, json: { results: [{ vulns: [{ id: FULL_RECORD.id, modified: "2024-01-01T00:00:00Z" }] }] } }
        : { status: 200, json: FULL_RECORD },
    );
    const [f] = await queryOsvBatch([{ name: "lodash", version: "4.17.20", ecosystem: "npm" }], "https://osv.test");
    expect(calls.map((c) => c.url)).toEqual([
      "https://osv.test/v1/querybatch",
      "https://osv.test/v1/vulns/GHSA-35jh-r3h4-6jhm",
    ]);
    expect(f).toMatchObject({
      severity: "HIGH",
      cveId: "CVE-2021-23337",
      cweId: "CWE-77",
      title: "GHSA-35jh-r3h4-6jhm: Command Injection in lodash",
      metadata: { fixVersion: "4.17.21", cvssScore: 7.2 },
    });
    expect(f.description).toContain("Upgrade to version 4.17.21");
  });

  it("keeps the finding (as before) when a detail lookup fails", async () => {
    mockOsv((url) =>
      url.endsWith("/v1/querybatch")
        ? { status: 200, json: { results: [{ vulns: [{ id: "GHSA-gone-0000-0000", modified: "x" }] }] } }
        : { status: 500, json: {} },
    );
    const [f] = await queryOsvBatch([{ name: "left-pad", version: "1.0.0", ecosystem: "npm" }], "https://osv.test");
    expect(f).toMatchObject({ ruleId: "GHSA-gone-0000-0000", severity: "MEDIUM" });
  });

  it("retries per ecosystem when OSV rejects the whole batch, so one bad ecosystem cannot drop the rest", async () => {
    const calls = mockOsv((url, body) => {
      if (url.endsWith("/v1/querybatch")) {
        const qs = (body as { queries: Array<{ package: { ecosystem: string } }> }).queries;
        if (qs.some((q) => q.package.ecosystem === "Bogus")) return { status: 400, json: { code: 3 } };
        return { status: 200, json: { results: qs.map(() => ({ vulns: [{ id: FULL_RECORD.id, modified: "x" }] })) } };
      }
      return { status: 200, json: FULL_RECORD };
    });
    const findings = await queryOsvBatch(
      [
        { name: "lodash", version: "4.17.20", ecosystem: "npm" },
        { name: "whatever", version: "1.0.0", ecosystem: "Bogus" },
      ],
      "https://osv.test",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].metadata).toMatchObject({ packageName: "lodash" });
    expect(calls.filter((c) => c.url.endsWith("/querybatch"))).toHaveLength(3);
  });
});
