import { describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

vi.mock("@/lib/api-key", () => ({ verifyApiKey: vi.fn(async (h: string | null) => (h ? { organizationId: "o1" } : null)) }));

import { POST } from "./route";
import { SECRET_PATTERNS } from "@/lib/precommit-secret-patterns";

async function scan(files: Array<{ path: string; content: string }>) {
  const res = await POST(
    new NextRequest("http://localhost/api/precommit/scan", {
      method: "POST",
      headers: { authorization: "Bearer ppr_x" },
      body: JSON.stringify({ files }),
    }),
  );
  return (await res.json()) as { findings: Array<{ ruleId: string; snippet: string; severity: string }>; shouldFail?: boolean };
}

describe("pre-commit secret scan", () => {
  it("uses the scanner's detectors (previously the list was empty)", () => {
    expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(14);
  });

  it("blocks real-looking secrets and never echoes them back", async () => {
    const key = "AKIAQ3ZRT5WJ4N6P2LMB";
    const { findings } = await scan([{ path: "config.js", content: `const k = "${key}";\n` }]);
    expect(findings).toEqual([expect.objectContaining({ ruleId: "SECRET-AWS_ACCESS_KEY", severity: "CRITICAL" })]);
    expect(findings[0].snippet).not.toContain(key);
  });

  it("keeps case-insensitive patterns case-insensitive", async () => {
    const { findings } = await scan([{ path: "id", content: "-----begin rsa private key-----\n" }]);
    expect(findings.map((f) => f.ruleId)).toContain("SECRET-PRIVATE_KEY");
  });

  it("ignores placeholders", async () => {
    const { findings } = await scan([{ path: "README.md", content: 'api_key = "your_api_key_example_here"\nAKIAEXAMPLEEXAMPLE12' }]);
    expect(findings).toEqual([]);
  });
});
