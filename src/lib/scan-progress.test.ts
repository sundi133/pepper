import { describe, it, expect } from "vitest";
import {
  computeScanProgress,
  reasoningTails,
  REASONING_PROGRESS_KEY,
  agentScanKeptCount,
  agentScanSummaryView,
} from "./scan-progress";

describe("agentScanKeptCount", () => {
  it("returns null when there is no agent-scan progress entry", () => {
    expect(agentScanKeptCount(null)).toBeNull();
    expect(agentScanKeptCount({})).toBeNull();
    expect(agentScanKeptCount({ AGENT_SCAN: { status: "DONE", reported: 14 } })).toBeNull();
  });

  it("returns the deduped/persisted findingsCount the worker recorded for the agent scanner", () => {
    // The banner must show this (matches the Findings tab), not the agent's
    // pre-dedup `reported` number.
    const scannerProgress = {
      "agent-scan": { status: "DONE", findingsCount: 10 },
      AGENT_SCAN: { status: "DONE", outcome: "completed", reported: 14 },
    };
    expect(agentScanKeptCount(scannerProgress)).toBe(10);
  });
});

describe("agentScanSummaryView", () => {
  it("returns null until the agent run has finished, and when there is no agent run", () => {
    expect(agentScanSummaryView(null)).toBeNull();
    expect(agentScanSummaryView({})).toBeNull();
    expect(agentScanSummaryView({ AGENT_SCAN: { status: "RUNNING" } })).toBeNull();
  });

  it("represents a FAILED run distinctly from a completed run that found nothing", () => {
    // The whole point of the fix: a 0-finding success and a failed run must not
    // look the same. Completed-with-zero is a neutral "info" result; a failed
    // run is a "warning" that explicitly says it is not clean.
    const cleanZero = agentScanSummaryView({
      "agent-scan": { status: "DONE", findingsCount: 0 },
      AGENT_SCAN: { status: "DONE", outcome: "completed", reported: 0 },
    });
    const failed = agentScanSummaryView({
      AGENT_SCAN: {
        status: "DONE",
        outcome: "failed",
        note: "OpenRouter 401: no credit",
      },
    });

    expect(cleanZero).toMatchObject({
      tone: "info",
      failed: false,
      completed: true,
      heading: "Agent deep scan: 0 findings",
    });
    expect(failed).toMatchObject({
      tone: "warning",
      failed: true,
      completed: false,
      heading: "Agent deep scan failed",
      note: "OpenRouter 401: no credit",
    });
    // They are unmistakably different representations.
    expect(failed?.tone).not.toBe(cleanZero?.tone);
    expect(failed?.heading).not.toBe(cleanZero?.heading);
  });

  it("marks a run that stopped early (incomplete) as a non-failed info result", () => {
    const view = agentScanSummaryView({
      "agent-scan": { status: "DONE", findingsCount: 2 },
      AGENT_SCAN: { status: "DONE", outcome: "incomplete", reported: 2 },
    });
    expect(view).toMatchObject({ tone: "info", failed: false, completed: true });
    expect(view?.heading).toBe("Agent deep scan stopped early: 2 findings");
  });

  it("marks a run that did not run (skipped) as a non-failed info result", () => {
    const view = agentScanSummaryView({
      AGENT_SCAN: { status: "DONE", outcome: "skipped", note: "agent not configured" },
    });
    expect(view).toMatchObject({
      tone: "info",
      failed: false,
      completed: false,
      heading: "Agent deep scan did not run",
    });
  });

  it("reports the deduped kept count and how many were deduped away", () => {
    const view = agentScanSummaryView({
      "agent-scan": { status: "DONE", findingsCount: 10 },
      AGENT_SCAN: { status: "DONE", outcome: "completed", reported: 14 },
    });
    expect(view).toMatchObject({ kept: 10, reported: 14, dedupedAway: 4 });
  });
});

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
