import { ScanContext, ScannerPlugin } from "../types";
import { runLlmSastScanner } from "./llm-analyzer";
import { runOpengrepScanner } from "./opengrep";

/**
 * Rule-based SAST: OpenGrep with the curated packs in rules/opengrep.
 * Deterministic and offline, so it runs whether or not LLM SAST is enabled.
 */
export const sastPatternScanner: ScannerPlugin = {
  name: "SAST_PATTERN",
  async scan(ctx: ScanContext) {
    return runOpengrepScanner(ctx);
  },
};

export const sastLlmScanner: ScannerPlugin = {
  name: "SAST_LLM",
  async scan(ctx: ScanContext) {
    return runLlmSastScanner(ctx);
  },
};
