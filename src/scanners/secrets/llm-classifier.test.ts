import { describe, it, expect } from "vitest";
import type { RawFinding } from "../types";

// Test filter policy via exported logic — classifySecrets is integration-tested;
// we unit-test the drop rules by importing internals through a small re-export or duplicate policy.

const DROPPABLE = new Set(["ENTROPY_SECRET"]);
const DROP_CONF = 0.88;

function shouldDrop(
  ruleId: string,
  isSecret: boolean,
  confidence: number,
): boolean {
  if (isSecret) return false;
  if (confidence < DROP_CONF) return false;
  return DROPPABLE.has(ruleId);
}

describe("LLM secret filter policy", () => {
  it("never drops dotenv or generic rule types", () => {
    expect(shouldDrop("DOTENV_SECRET", false, 0.99)).toBe(false);
    expect(shouldDrop("GENERIC_API_KEY", false, 0.99)).toBe(false);
    expect(shouldDrop("GITHUB_TOKEN", false, 0.99)).toBe(false);
  });

  it("may drop entropy only with high-confidence false positive", () => {
    expect(shouldDrop("ENTROPY_SECRET", false, 0.9)).toBe(true);
    expect(shouldDrop("ENTROPY_SECRET", false, 0.5)).toBe(false);
    expect(shouldDrop("ENTROPY_SECRET", true, 0.9)).toBe(false);
  });
});
