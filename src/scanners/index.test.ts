import * as assert from "node:assert/strict";
import { describe, it } from "node:test";
import { getScanners } from "./index";

describe("getScanners", () => {
  it("uses AI SAST instead of pattern SAST when provider API key is configured", () => {
    const scanners = getScanners("SAST_ONLY", {
      enableLlmSast: true,
      enableLlmSecrets: false,
      llmProvider: "openrouter",
      llmApiKey: "sk-test",
    }).map((scanner) => scanner.name);

    assert.deepEqual(scanners, ["SAST_LLM", "IAC"]);
    assert.ok(!scanners.includes("SAST_PATTERN"));
  });

  it("falls back to pattern SAST when AI SAST has no provider key", () => {
    const scanners = getScanners("SAST_ONLY", {
      enableLlmSast: true,
      enableLlmSecrets: false,
      llmProvider: "openrouter",
    }).map((scanner) => scanner.name);

    assert.ok(scanners.includes("SAST_PATTERN"));
    assert.ok(!scanners.includes("SAST_LLM"));
  });
});
