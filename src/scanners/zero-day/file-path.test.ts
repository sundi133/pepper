import { describe, it, expect, vi } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const answer = vi.fn();
vi.mock("@/lib/llm-gateway", async (orig) => ({
  ...(await orig<typeof import("@/lib/llm-gateway")>()),
  createLlmClient: () => ({ type: "openai", client: {}, model: "m" }),
  analyzeWithLlm: () => answer(),
}));

import { resolveSentFile, zeroDayScanner } from "./index";

const finding = (filePath: unknown, extra: Record<string, unknown> = {}) => ({
  title: "Any user can change another user's password",
  severity: "HIGH",
  category: "IDOR",
  description: "The account is looked up from the path parameter, not the token subject.",
  filePath,
  startLine: 3,
  endLine: 4,
  cweId: "CWE-639",
  confidence: 0.9,
  attackVector: "PUT /users/v1/victim/password with the attacker's token.",
  recommendation: "Look the account up from the verified token subject.",
  ...extra,
});

describe("resolveSentFile", () => {
  const sent = ["api_views/users.py", "api_views/books.py", "models/user_model.py"];
  it("matches the path as sent, with ./, a leading slash or backslashes", () => {
    expect(resolveSentFile("api_views/users.py", sent)).toBe("api_views/users.py");
    expect(resolveSentFile("./api_views/users.py", sent)).toBe("api_views/users.py");
    expect(resolveSentFile("/api_views/users.py", sent)).toBe("api_views/users.py");
    expect(resolveSentFile("api_views\\users.py", sent)).toBe("api_views/users.py");
  });
  it("matches a unique tail or a path with an extra leading folder", () => {
    expect(resolveSentFile("books.py", sent)).toBe("api_views/books.py");
    expect(resolveSentFile("vampi/api_views/books.py", sent)).toBe("api_views/books.py");
  });
  it("rejects missing, unknown and ambiguous paths", () => {
    expect(resolveSentFile(undefined, sent)).toBeUndefined();
    expect(resolveSentFile("", sent)).toBeUndefined();
    expect(resolveSentFile("api_views/admin.py", sent)).toBeUndefined();
    expect(resolveSentFile("users.py", ["a/users.py", "b/users.py"])).toBeUndefined();
  });
});

describe("ZERO_DAY keeps findings that point at a sent file", () => {
  it("keeps them with the sent path, and drops unknown files and low confidence", async () => {
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "pepper-zd-path-"));
    try {
      fs.mkdirSync(path.join(workDir, "api_views"));
      fs.writeFileSync(path.join(workDir, "api_views/users.py"), "def update_password(username):\n    user = User.query.filter_by(username=username).first()\n    user.password = body['password']\n    db.session.commit()\n");
      answer.mockResolvedValue(
        JSON.stringify({
          findings: [
            finding("./api_views/users.py"),
            finding("api_views/not_sent.py"),
            finding("api_views/users.py", { confidence: 0.5, title: "weak" }),
          ],
        }),
      );
      const out = await zeroDayScanner.scan({
        workDir,
        fileList: ["api_views/users.py"],
        scanType: "ZERO_DAY_ONLY",
        orgSettings: { llmProvider: "openai", llmBaseUrl: "", llmModel: "m", llmApiKey: "k", enableLlmSast: true, enableLlmSecrets: false, osvApiUrl: "", vulnDbMode: "offline" },
      } as never);
      expect(out).toHaveLength(1);
      expect(out[0].filePath).toBe("api_views/users.py");
      expect(out[0].cweId).toBe("CWE-639");
      expect(out[0].snippet).toContain("filter_by(username=username)");
    } finally {
      fs.rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("asks for filePath in the answer format", async () => {
    const { ZERO_DAY_SYSTEM_PROMPT } = await import("./prompts");
    expect(ZERO_DAY_SYSTEM_PROMPT).toMatch(/"filePath":/);
  });
});

describe("coveredByMainPass", () => {
  it("drops a rule finding when the main pass reported an authorization flaw in the same handler", async () => {
    const { coveredByMainPass } = await import("./index");
    const logic = { scanner: "ZERO_DAY", severity: "HIGH", title: "[Zero-Day] debug lacks authentication", filePath: "api/users.py", startLine: 25, cweId: "CWE-306", metadata: { handlerRange: "api/users.py:23-28" } } as never;
    const mainAuthz = { scanner: "ZERO_DAY", severity: "HIGH", title: "[Zero-Day] Unauthenticated debug endpoint exposes passwords", filePath: "api/users.py", startLine: 24, cweId: "CWE-200" } as never;
    const mainOther = { scanner: "ZERO_DAY", severity: "HIGH", title: "[Zero-Day] SQL injection in debug", filePath: "api/users.py", startLine: 24, cweId: "CWE-89" } as never;
    expect(coveredByMainPass(logic, [mainAuthz])).toBe(true);
    expect(coveredByMainPass(logic, [mainOther])).toBe(false);
    const pattern = { scanner: "ZERO_DAY", severity: "HIGH", title: "x", filePath: "a.js", startLine: 10, cweId: "CWE-362", metadata: {} } as never;
    expect(coveredByMainPass(pattern, [{ ...(pattern as object), startLine: 12 } as never])).toBe(true);
    expect(coveredByMainPass(pattern, [{ ...(pattern as object), startLine: 30 } as never])).toBe(false);
  });
});
