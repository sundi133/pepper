import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/auth-guard", () => ({
  requireAuth: vi.fn(async () => ({ session: { user: { id: "u1" } } })),
  getDefaultOrgId: vi.fn(() => "o1"),
}));

const scanFindFirst = vi.fn();
const findingFindMany = vi.fn();
const findingUpdate = vi.fn();

vi.mock("@/lib/prisma", () => ({
  prisma: {
    scan: { findFirst: (...a: unknown[]) => scanFindFirst(...a) },
    finding: {
      findMany: (...a: unknown[]) => findingFindMany(...a),
      update: (...a: unknown[]) => findingUpdate(...a),
    },
  },
}));

import { GET } from "./route";

const getExport = (query = "") =>
  GET(new NextRequest(`http://localhost/api/scans/s1/findings/export${query}`), {
    params: Promise.resolve({ scanId: "s1" }),
  });

beforeEach(() => {
  vi.clearAllMocks();
  scanFindFirst.mockResolvedValue({
    id: "s1",
    status: "COMPLETED",
    scanType: "FULL",
    branch: "main",
    commitSha: "abc1234567890",
    sourceType: "GIT",
    sourceRef: null,
    gateResult: "FAILED",
    createdAt: new Date("2026-10-05T10:00:00Z"),
    completedAt: new Date("2026-10-05T10:05:00Z"),
    filesScanned: 42,
    depsScanned: 150,
    criticalCount: 1,
    highCount: 1,
    mediumCount: 1,
    lowCount: 0,
    infoCount: 0,
    project: { name: "vuln-app", repoUrl: "https://github.com/vulnerable-apps/vuln-app" },
  });
});

describe("findings export: HTML viewer output", () => {
  it("renders rich HTML report with metric cards, scanner category pills, and parity with UI", async () => {
    findingFindMany.mockResolvedValue([
      {
        id: "f1",
        scanner: "SAST_LLM",
        severity: "CRITICAL",
        title: "Command Injection via GraphQL Mutation",
        description: "User-controlled input from command reaches child_process.exec.",
        filePath: "app/lib/gql/mutations/secret_mutation.ts",
        startLine: 20,
        endLine: 32,
        snippet: 'child_process.exec(command, (err, stdout) => { ... })',
        ruleId: "CWE-78",
        cweId: "CWE-78",
        cveId: null,
        confidence: 1.0,
        status: "OPEN",
        metadata: {
          generatedDetails: {
            summary: "What is wrong: User input reaches child_process.exec without validation.\n\nWhy it is exploitable: Enables arbitrary command injection.",
            stepsToReproduce: [
              "Identify the GraphQL endpoint.",
              "Send a mutation with command injection payload:\n```graphql\nmutation { secretMutation(command: \"id\") { stdout } }\n```",
              "Observe the command output in stdout.",
            ],
            impact: "Remote Code Execution (RCE) on the server.",
            remediation: [
              "Do not execute user-provided commands directly on the server.",
              "Use an allowlist of permitted commands.",
            ],
            references: "* CWE-78 – Command Injection",
          },
        },
      },
      {
        id: "f2",
        scanner: "SAST_PATTERN",
        severity: "CRITICAL",
        title: "Improper neutralization of special elements in data query logic",
        description: "Found SQL query built from string concatenation.\n\nReport:\nWhat is wrong: unescaped input",
        filePath: "app/lib/gql/mutations/authentication.ts",
        startLine: 80,
        endLine: 85,
        snippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
        ruleId: "CWE-943",
        cweId: "CWE-943",
        cveId: null,
        confidence: 0.95,
        status: "OPEN",
        metadata: {},
      },
      {
        id: "f3",
        scanner: "SCA",
        severity: "HIGH",
        title: "Prototype Pollution in lodash",
        description: "lodash before 4.17.21 is vulnerable to prototype pollution.",
        filePath: "package.json",
        startLine: 12,
        endLine: 12,
        snippet: '"lodash": "4.17.15"',
        ruleId: "CVE-2020-8203",
        cweId: "CWE-1321",
        cveId: "CVE-2020-8203",
        confidence: 1.0,
        status: "OPEN",
        metadata: {
          packageName: "lodash",
          currentVersion: "4.17.15",
          fixVersion: "4.17.21",
          usageLocations: [
            { filePath: "src/utils.js", line: 45, usage: "lodash.defaultsDeep({}, input)" },
          ],
        },
      },
      {
        id: "f4",
        scanner: "SECRETS_PATTERN",
        severity: "MEDIUM",
        title: "AWS: AWS Access Key ID",
        description: "Exposed AWS Access Key in repository configuration.",
        filePath: "config/aws.env",
        startLine: 5,
        endLine: 5,
        snippet: "AKIAIOSFODNN7EXAMPLE",
        ruleId: "AWS-ACCESS-KEY",
        cweId: "CWE-798",
        cveId: null,
        confidence: 0.9,
        status: "OPEN",
        metadata: {
          secretType: "AWS Access Key",
        },
      },
    ]);

    const res = await getExport("?format=html");
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/html");

    const html = await res.text();

    // Verify Header and Hero Cards
    expect(html).toContain("Pepper SAST · Security Assessment Report");
    expect(html).toContain("vuln-app");
    expect(html).toContain("Gate FAILED");
    expect(html).toContain("https://github.com/vulnerable-apps/vuln-app");

    // Verify Metrics and Scanner Breakdown Pills
    expect(html).toContain('<div class="metric-val">2</div>'); // 2 Criticals
    expect(html).toContain('<div class="metric-val">4</div>'); // 4 Total findings
    expect(html).toContain("SAST Findings (2)");
    expect(html).toContain("SCA Findings (1)");
    expect(html).toContain("Secrets Findings (1)");

    // Verify SAST (AI) card content & code blocks
    expect(html).toContain("Command Injection via GraphQL Mutation");
    expect(html).toContain("Confidence: 100%");
    expect(html).toContain("app/lib/gql/mutations/secret_mutation.ts:20-32");
    expect(html).toContain("What is wrong:");
    expect(html).toContain("mutation { secretMutation(command: &quot;id&quot;) { stdout } }");
    expect(html).toContain("Remote Code Execution (RCE)");

    // Verify SAST (Pattern) card notice & code evidence
    expect(html).toContain("This match comes from a <strong>pattern-based</strong> rule");
    expect(html).toContain("Found SQL query built from string concatenation.");
    expect(html).toContain("db.query(&quot;SELECT * FROM users WHERE id = &quot; + id)");

    // Verify SCA card dependency grid and usage locations
    expect(html).toContain("Package Name");
    expect(html).toContain("lodash");
    expect(html).toContain("4.17.15");
    expect(html).toContain("4.17.21");
    expect(html).toContain("Where Used In Source Code");
    expect(html).toContain("src/utils.js");
    expect(html).toContain("lodash.defaultsDeep({}, input)");

    // Verify Secret card
    expect(html).toContain("Secrets Identified");
    expect(html).toContain("AWS Access Key");
    expect(html).toContain("****");
    expect(html).toContain("This secret was found in source code");
  });
});
