import { ScanContext, ScannerPlugin } from "../types";
import { runLlmSastScanner } from "./llm-analyzer";

export const sastLlmScanner: ScannerPlugin = {
  name: "SAST_LLM",
  async scan(ctx: ScanContext) {
    return runLlmSastScanner(ctx);
  },
};
