import { describe, expect, it } from "vitest";
import { applyRunEvent, initialRunView } from "./run-reducer";
import { parseDecision, stripDecision } from "./prompts";
import { remediationBranchName, resolveFindingPath } from "./workspace";
import type { RemediationRunSnapshot, RemediationStreamEvent } from "./types";

const snapshot: RemediationRunSnapshot = {
  id: "run1",
  scanId: "scan1",
  status: "QUEUED",
  provider: "github",
  repoUrl: "https://github.com/a/b",
  baseBranch: "main",
  headBranch: null,
  prUrl: null,
  prNumber: null,
  errorMessage: null,
  fixedCount: 0,
  failedCount: 0,
  cancelRequested: false,
  createdAt: "2026-09-26T00:00:00.000Z",
  startedAt: null,
  completedAt: null,
  items: [
    { id: "i1", findingId: "f1", position: 0, status: "PENDING", title: "SQLi", severity: "HIGH", filePath: "a.ts" },
    { id: "i2", findingId: "f2", position: 1, status: "PENDING", title: "XSS", severity: "LOW", filePath: "b.ts" },
  ],
};

let seq = 0;
const ev = (e: Record<string, unknown>) =>
  ({ ...e, seq: ++seq, at: "2026-09-26T00:00:01.000Z" }) as unknown as RemediationStreamEvent;

describe("applyRunEvent", () => {
  it("folds a full run into the view model", () => {
    seq = 0;
    const events = [
      ev({ type: "run_started", total: 2, provider: "GitHub", repoUrl: "r", baseBranch: "main", headBranch: "pepper/x", model: "m" }),
      ev({ type: "item_started", itemId: "i1", index: 0, title: "SQLi", filePath: "a.ts" }),
      ev({ type: "step", itemId: "i1", step: "analyze", status: "running", message: "…" }),
      ev({ type: "analysis_delta", itemId: "i1", text: "### Assessment\nReal" }),
      ev({ type: "analysis_delta", itemId: "i1", text: " issue." }),
      ev({ type: "fix_proposed", itemId: "i1", attempt: 1, summary: "param", diff: "+x", files: ["a.ts"] }),
      ev({ type: "validation", itemId: "i1", attempt: 1, passed: true, checks: [] }),
      ev({ type: "item_done", itemId: "i1", status: "FIXED", reason: "param", commitSha: "abc" }),
      ev({ type: "item_started", itemId: "i2", index: 1, title: "XSS", filePath: "b.ts" }),
      ev({ type: "item_done", itemId: "i2", status: "SKIPPED", reason: "false positive" }),
      ev({ type: "pr_opening", branch: "pepper/x", commits: 1 }),
      ev({ type: "run_done", status: "PARTIAL", fixed: 1, failed: 0, skipped: 1, prUrl: "https://pr", prNumber: 7 }),
    ];
    const view = events.reduce(applyRunEvent, initialRunView(snapshot));
    expect(view.status).toBe("PARTIAL");
    expect(view.prUrl).toBe("https://pr");
    expect(view.prNumber).toBe(7);
    expect(view.items[0].analysis).toBe("### Assessment\nReal issue.");
    expect(view.items[0].attempts[0].validation?.passed).toBe(true);
    expect(view.items[0].status).toBe("FIXED");
    expect(view.items[1].status).toBe("SKIPPED");
    expect(view.counts).toEqual({ fixed: 1, failed: 0, skipped: 1 });
  });

  it("ignores replayed events (reconnect with Last-Event-ID)", () => {
    seq = 0;
    const delta = ev({ type: "analysis_delta", itemId: "i1", text: "once" });
    const v1 = applyRunEvent(initialRunView(snapshot), delta);
    const v2 = applyRunEvent(v1, delta);
    expect(v2.items[0].analysis).toBe("once");
  });

  it("clears later steps when a fix is retried", () => {
    seq = 0;
    let v = initialRunView(snapshot);
    for (const e of [
      ev({ type: "step", itemId: "i1", step: "validate", status: "failed", message: "x" }),
      ev({ type: "step", itemId: "i1", step: "fix", status: "running", message: "retry" }),
    ]) {
      v = applyRunEvent(v, e);
    }
    expect(v.items[0].steps.validate).toBeUndefined();
    expect(v.items[0].status).toBe("FIXING");
  });
});

describe("parseDecision / stripDecision", () => {
  it("reads the last DECISION line and defaults to fix", () => {
    expect(parseDecision("…\nDECISION: false_positive")).toBe("false_positive");
    expect(parseDecision("DECISION: fix\nlater\nDECISION: needs_human")).toBe("needs_human");
    expect(parseDecision("no decision")).toBe("fix");
    expect(stripDecision("### A\ntext\nDECISION: fix\n")).toBe("### A\ntext");
  });
});

describe("resolveFindingPath", () => {
  const files = ["src/app.ts", "src/lib/db.ts", "lib/db.ts"];
  it("matches exact, archive-prefixed and unique-basename paths", () => {
    expect(resolveFindingPath("src/app.ts", files)).toBe("src/app.ts");
    expect(resolveFindingPath("repo-main/src/app.ts", files)).toBe("src/app.ts");
    expect(resolveFindingPath("x/y/app.ts", files)).toBe("src/app.ts");
  });
  it("refuses ambiguous basenames and unsafe paths", () => {
    expect(resolveFindingPath("other/db.ts", files)).toBeNull();
    expect(resolveFindingPath("../src/app.ts", files)).toBeNull();
    expect(resolveFindingPath(null, files)).toBeNull();
  });
});

describe("remediationBranchName", () => {
  it("is git-safe and date-stamped", () => {
    expect(remediationBranchName("cmabcDEF12345678", new Date("2026-09-26T10:00:00Z"))).toBe(
      "pepper/ai-remediation-20260926-12345678",
    );
  });
});
