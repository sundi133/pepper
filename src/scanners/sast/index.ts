import { ScanContext, ScannerPlugin } from "../types";
import { runLlmSastScanner } from "./llm-analyzer";

/** Pattern-based SAST is quarantined — never registered or run. */
export const sastPatternScanner: ScannerPlugin = {
  name: "SAST_PATTERN",
  async scan(): Promise<never[]> {
    return [];
  },
};

export const sastLlmScanner: ScannerPlugin = {
  name: "SAST_LLM",
  async scan(ctx: ScanContext) {
    return runLlmSastScanner(ctx);
  },
};
