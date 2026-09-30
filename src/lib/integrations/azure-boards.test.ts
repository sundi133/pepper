import { afterEach, describe, expect, it, vi } from "vitest";
import {
  boardsAuth,
  boardsError,
  boardsConfigError,
  boardsTarget,
  buildWorkItemOps,
  createWorkItem,
  markdownToSafeHtml,
  markWorkItemFixed,
  validateBoardsConfig,
  workItemTags,
  workItemTitle,
  type BoardsFindingInput,
} from "./azure-boards";
import type { AzureBoardsConfig } from "./types";

const cloud: AzureBoardsConfig = { organization: "acme", project: "Payments" };
const auth = { organization: "acme", pat: "pat-123" };
const finding: BoardsFindingInput = {
  pepperFindingId: "f1",
  title: "SQL injection in order lookup",
  severity: "HIGH",
  description: "User input reaches a query.\n\n**Fix:** use parameters.",
  filePath: "src/orders.ts",
  line: 42,
  cweId: "CWE-89",
  scanUrl: "https://pepper.local/scans/s1",
};

type Call = { url: string; init: RequestInit };
function mockFetch(...responses: Array<{ status: number; body?: unknown }>) {
  const calls: Call[] = [];
  const queue = [...responses];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      const r = queue.shift() ?? { status: 500, body: { message: "unexpected call" } };
      return new Response(r.body === undefined ? "" : JSON.stringify(r.body), { status: r.status });
    }),
  );
  return calls;
}
const opsOf = (c: Call) => JSON.parse(String(c.init.body)) as Array<{ path: string; value: unknown }>;
const paths = (c: Call) => opsOf(c).map((o) => o.path);

afterEach(() => vi.unstubAllGlobals());

describe("work item content", () => {
  it("escapes repository content and keeps simple formatting", () => {
    const html = markdownToSafeHtml("Bad <script>alert(1)</script> **bold** `x<y`\n\n- one\n- two\n\n```js\nif (a < b) run();\n```");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("<b>bold</b>");
    expect(html).toContain("<code>x&lt;y</code>");
    expect(html).toContain("<ul><li>one</li><li>two</li></ul>");
    expect(html).toContain("<pre><code>if (a &lt; b) run();</code></pre>");
  });

  it("caps titles and sanitises tags", () => {
    expect(workItemTitle({ ...finding, title: "x".repeat(400) })).toHaveLength(255);
    expect(workItemTags({ ...cloud, tags: ["app;sec", "security", " "] }, finding)).toBe(
      "pepper; security; severity-high; CWE-89; app sec",
    );
  });

  it("sends Bug-only fields only for Bugs, and drops optional fields on retry", () => {
    const bug = buildWorkItemOps({ ...cloud, areaPath: "Payments\\AppSec", assignedTo: "a@b.c" }, finding, true);
    expect(bug.map((o) => o.path)).toEqual([
      "/fields/System.Title",
      "/fields/System.Description",
      "/fields/System.Tags",
      "/fields/System.AreaPath",
      "/fields/System.AssignedTo",
      "/fields/Microsoft.VSTS.Common.Priority",
      "/fields/Microsoft.VSTS.TCM.ReproSteps",
      "/fields/Microsoft.VSTS.Common.Severity",
      "/relations/-",
    ]);
    expect(bug.find((o) => o.path.endsWith("Severity"))?.value).toBe("2 - High");
    const issue = buildWorkItemOps({ ...cloud, workItemType: "Issue" }, finding, true).map((o) => o.path);
    expect(issue).toContain("/fields/Microsoft.VSTS.Common.Priority");
    expect(issue).not.toContain("/fields/Microsoft.VSTS.TCM.ReproSteps");
    const minimal = buildWorkItemOps({ ...cloud, areaPath: "Payments\\AppSec" }, finding, false).map((o) => o.path);
    expect(minimal).toContain("/fields/System.AreaPath");
    expect(minimal).not.toContain("/fields/Microsoft.VSTS.Common.Priority");
  });
});

describe("config", () => {
  it("identifies the board independent of case and trailing slashes", () => {
    expect(boardsTarget(cloud, "Payments")).toBe("https://dev.azure.com/acme/payments");
    expect(boardsTarget({ ...cloud, serverUrl: "https://TFS.corp/tfs/" }, "Payments")).toBe("https://tfs.corp/tfs/acme/payments");
  });

  it("prefers the integration PAT, else reuses the repository connection", () => {
    expect(boardsAuth({ ...cloud, pat: "own" }, { organization: "x", pat: "conn" })?.pat).toBe("own");
    expect(boardsAuth(cloud, { organization: "x", pat: "conn" })).toEqual({ organization: "acme", pat: "conn" });
    expect(boardsAuth({ ...cloud, serverUrl: "https://tfs.corp" }, { organization: "x", pat: "conn" })?.serverUrl).toBe("https://tfs.corp");
    expect(boardsAuth(cloud, null)).toBeNull();
  });

  it("uses the on-prem connection's server when the board's Server URL is blank", () => {
    const onPrem = { organization: "DefaultCollection", pat: "conn", serverUrl: "http://ado-server" };
    const board: AzureBoardsConfig = { organization: "DefaultCollection", project: "PepperTest" };
    // Reuses the connection's PAT → same server.
    expect(boardsAuth(board, onPrem)).toEqual({ organization: "DefaultCollection", pat: "conn", serverUrl: "http://ado-server" });
    // Own PAT, same collection (case-insensitive) → same server.
    expect(boardsAuth({ ...board, organization: "defaultcollection", pat: "own" }, onPrem)?.serverUrl).toBe("http://ado-server");
    // Own PAT and a different organization → still Azure DevOps Services.
    expect(boardsAuth({ ...board, organization: "acme", pat: "own" }, onPrem)?.serverUrl).toBeUndefined();
    // An explicit Server URL always wins.
    expect(boardsAuth({ ...board, serverUrl: "https://tfs.corp" }, onPrem)?.serverUrl).toBe("https://tfs.corp");
  });

  it("rejects unusable configs", () => {
    expect(boardsConfigError(cloud)).toBeNull();
    expect(boardsConfigError({ ...cloud, organization: " " })).toMatch(/Organization/);
    expect(boardsConfigError({ ...cloud, serverUrl: "ftp://x" })).toMatch(/http/);
    expect(boardsConfigError({ ...cloud, autoCreateSeverities: ["INFO" as never] })).toMatch(/autoCreate/);
  });
});

describe("REST", () => {
  it("creates a work item with JSON Patch and returns the web link", async () => {
    const calls = mockFetch({ status: 200, body: { id: 77, _links: { html: { href: "https://dev.azure.com/acme/Payments/_workitems/edit/77" } } } });
    const ref = await createWorkItem(auth, cloud, "Payments", finding);
    expect(ref).toEqual({ id: "77", url: "https://dev.azure.com/acme/Payments/_workitems/edit/77" });
    expect(calls[0].url).toBe("https://dev.azure.com/acme/Payments/_apis/wit/workitems/$Bug?api-version=7.1");
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json-patch+json");
    expect(headers.Authorization).toBe(`Basic ${Buffer.from(":pat-123").toString("base64")}`);
  });

  it("targets Azure DevOps Server with the configured api-version, retrying without optional fields", async () => {
    const calls = mockFetch({ status: 400, body: { message: "TF51535: Cannot find field Microsoft.VSTS.Common.Severity." } }, { status: 200, body: { id: 5 } });
    const server = { ...cloud, serverUrl: "https://tfs.corp/tfs", organization: "DefaultCollection", apiVersion: "6.0" };
    const ref = await createWorkItem({ organization: "DefaultCollection", pat: "p", serverUrl: "https://tfs.corp/tfs" }, server, "Payments", finding);
    expect(calls[1].url).toBe("https://tfs.corp/tfs/DefaultCollection/Payments/_apis/wit/workitems/$Bug?api-version=6.0");
    expect(paths(calls[0])).toContain("/fields/Microsoft.VSTS.Common.Severity");
    expect(paths(calls[1])).not.toContain("/fields/Microsoft.VSTS.Common.Severity");
    expect(ref.url).toBe("https://tfs.corp/tfs/DefaultCollection/Payments/_workitems/edit/5");
  });

  it("explains rejected PATs and unsupported api-versions", async () => {
    mockFetch({ status: 203, body: "<html>sign in</html>" });
    await expect(createWorkItem(auth, cloud, "Payments", finding)).rejects.toThrow(/Work Items \(Read & write\)/);
    mockFetch(
      { status: 400, body: { message: "The requested REST API version of 7.1 is out of range for this server." } },
      { status: 400, body: { message: "The requested REST API version of 7.1 is out of range for this server." } },
    );
    await expect(createWorkItem(auth, cloud, "Payments", finding)).rejects.toThrow(/6\.0 for Server 2020/);
  });

  it("marks fixed: comments always, moves state only when still open", async () => {
    let calls = mockFetch({ status: 200, body: { fields: { "System.State": "Active" } } }, { status: 200, body: { id: 7 } });
    expect(await markWorkItemFixed(auth, { ...cloud, fixedState: "Resolved" }, "Payments", "7", {})).toBe(true);
    expect(paths(calls[1])).toEqual(["/fields/System.History", "/fields/System.State"]);

    calls = mockFetch({ status: 200, body: { fields: { "System.State": "Closed" } } }, { status: 200, body: { id: 7 } });
    await markWorkItemFixed(auth, { ...cloud, fixedState: "Resolved" }, "Payments", "7", {});
    expect(paths(calls[1])).toEqual(["/fields/System.History"]);

    calls = mockFetch({ status: 200, body: { fields: { "System.State": "New" } } }, { status: 400, body: { message: "invalid state" } }, { status: 200, body: { id: 7 } });
    await markWorkItemFixed(auth, { ...cloud, fixedState: "Fixed" }, "Payments", "7", {});
    expect(paths(calls[2])).toEqual(["/fields/System.History"]);

    mockFetch({ status: 404, body: { message: "gone" } });
    expect(await markWorkItemFixed(auth, cloud, "Payments", "7", {})).toBe(false);
  });

  it("validates without creating anything", async () => {
    let calls = mockFetch({ status: 200, body: { name: "Bug" } }, { status: 200, body: {} });
    await expect(validateBoardsConfig(auth, { ...cloud, areaPath: "Payments\\AppSec" }, "Payments")).resolves.toEqual({ workItemType: "Bug" });
    expect(calls.every((c) => (c.init.method ?? "GET") === "GET")).toBe(true);
    expect(calls[1].url).toContain("/Payments/_apis/wit/classificationnodes/Areas/AppSec?");

    mockFetch({ status: 404, body: { message: "not found" } });
    await expect(validateBoardsConfig(auth, cloud, "Payments")).rejects.toThrow(/Basic-process projects use "Issue"/);

    calls = mockFetch({ status: 200, body: {} });
    await validateBoardsConfig(auth, cloud, null);
    expect(calls[0].url).toBe("https://dev.azure.com/acme/_apis/wit/fields/System.Title?api-version=7.1");
  });
});

describe("boardsError", () => {
  const rejected = { ok: false, status: 203, data: "<html>sign in</html>", raw: "" } as never;
  it("names the host and points at the Server URL when the PAT is rejected", () => {
    expect(boardsError("Azure Boards check", rejected).message).toMatch(
      /dev\.azure\.com rejected the PAT\. Check the Server URL: it's blank, which means Azure DevOps Services .*Work Items \(Read & write\)/,
    );
    expect(
      boardsError("Azure Boards check", rejected, { organization: "DefaultCollection", pat: "p", serverUrl: "http://ado-server:8080/tfs" }).message,
    ).toMatch(/ado-server:8080 rejected the PAT\. Check the Server URL \(ado-server:8080\)/);
  });
});
