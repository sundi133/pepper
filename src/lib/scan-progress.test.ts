import { describe, it, expect } from "vitest";
import {
  computeScanProgress,
  reasoningTails,
  REASONING_PROGRESS_KEY,
} from "./scan-progress";

describe("reasoningTails", () => {
  it("returns null when there is no __reasoning__ entry", () => {
    expect(reasoningTails(null)).toBeNull();
    expect(reasoningTails({})).toBeNull();
    expect(reasoningTails({ SAST_LLM: { status: "DONE" } })).toBeNull();
  });

  it("returns the non-empty per-scanner tails", () => {
    const tails = reasoningTails({
      SAST_LLM: { status: "RUNNING" },
      [REASONING_PROGRESS_KEY]: {
        SAST_LLM: "tracing the taint",
        SECRETS_LLM: "  ",
        ZERO_DAY: "checking the handler",
      },
    });
    expect(tails).toEqual({
      SAST_LLM: "tracing the taint",
      ZERO_DAY: "checking the handler",
    });
  });

  it("returns null when every tail is blank", () => {
    expect(
      reasoningTails({ [REASONING_PROGRESS_KEY]: { SAST_LLM: "" } }),
    ).toBeNull();
  });
});

describe("computeScanProgress ignores the __reasoning__ entry", () => {
  it("does not let the reasoning store dilute the scanner count", () => {
    const withoutReasoning = computeScanProgress(
      { SAST_LLM: { status: "DONE" }, SECRETS_LLM: { status: "DONE" } },
      "RUNNING",
    );
    const withReasoning = computeScanProgress(
      {
        SAST_LLM: { status: "DONE" },
        SECRETS_LLM: { status: "DONE" },
        [REASONING_PROGRESS_KEY]: { SAST_LLM: "thinking…" } as never,
      },
      "RUNNING",
    );
    expect(withReasoning).toBe(withoutReasoning);
  });

  it("returns 10 when the only entry is the reasoning store", () => {
    expect(
      computeScanProgress(
        { [REASONING_PROGRESS_KEY]: { SAST_LLM: "thinking…" } as never },
        "RUNNING",
      ),
    ).toBe(10);
  });
});
