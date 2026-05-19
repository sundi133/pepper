import { describe, it, expect } from "vitest";
import {
  scanLinesForSecrets,
  secretCandidateId,
  secretHitsToRawFindings,
} from "./engine";

describe("scanLinesForSecrets", () => {
  it("detects AWS key and prefers specific rule over generic secret", () => {
    const lines = ['AWS_ACCESS_KEY_ID = "AKIA0000000000000000"'];
    const hits = scanLinesForSecrets(lines, "config.ts");
    const ruleIds = hits.map((h) => h.ruleId);
    expect(ruleIds).toContain("AWS_ACCESS_KEY");
    expect(ruleIds).not.toContain("GENERIC_SECRET");
  });

  it("deduplicates same rule on same line", () => {
    const lines = ['api_key = "abcdefghijklmnopqrstuvwxyz"'];
    const hits = scanLinesForSecrets(lines, "app.ts");
    const generic = hits.filter((h) => h.ruleId === "GENERIC_API_KEY");
    expect(generic).toHaveLength(1);
  });

  it("skips entropy when a pattern already matched", () => {
    const lines = [
      'github_token = "ghp_1234567890123456789012345678901234567890"',
    ];
    const hits = scanLinesForSecrets(lines, "tokens.ts");
    expect(hits.some((h) => h.ruleId === "GITHUB_TOKEN")).toBe(true);
    expect(hits.some((h) => h.ruleId === "ENTROPY_SECRET")).toBe(false);
  });

  it("detects unquoted secrets in .env files", () => {
    const lines = [
      "DB_PASSWORD=MySuperSecretPassword123",
      "API_KEY=abcdefghijklmnopqrstuvwxyz",
    ];
    const hits = scanLinesForSecrets(lines, ".env");
    expect(hits.some((h) => h.ruleId === "DOTENV_SECRET")).toBe(true);
  });

  it("skips env reference lines for entropy", () => {
    const lines = [
      'const key = process.env.API_KEY || "fallback-not-used-here"',
    ];
    const hits = scanLinesForSecrets(lines, "env.ts");
    expect(hits.some((h) => h.ruleId === "ENTROPY_SECRET")).toBe(false);
  });
});

describe("secretCandidateId", () => {
  it("builds stable ids from file, line, and rule", () => {
    const [raw] = secretHitsToRawFindings(
      [
        {
          ruleId: "AWS_ACCESS_KEY",
          title: "t",
          description: "d",
          severity: "CRITICAL",
          startLine: 3,
          endLine: 3,
          snippet: "x",
          confidence: 0.85,
          masked: true,
        },
      ],
      "src/config.ts",
    );
    expect(secretCandidateId(raw)).toBe("src/config.ts:3:AWS_ACCESS_KEY");
  });
});
