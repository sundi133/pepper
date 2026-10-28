import { describe, it, expect } from "vitest";
import { completionCopy } from "./scan-notifications";

const none = { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, newFindingCount: 0 };

describe("completionCopy", () => {
  it("leads with critical issues and lists every severity present", () => {
    const copy = completionCopy(
      "api",
      { criticalCount: 2, highCount: 5, mediumCount: 0, lowCount: 1, newFindingCount: 3 },
      false,
    );
    expect(copy.title).toBe("Scan completed: 2 critical issues");
    expect(copy.body).toBe("Security scan finished for api: 2 critical, 5 high, 1 low (3 new).");
  });

  it("falls back to high, then to a plain title", () => {
    expect(completionCopy("api", { ...none, highCount: 1 }, false).title).toBe(
      "Scan completed: 1 high issue",
    );
    const clean = completionCopy("api", none, false);
    expect(clean.title).toBe("Scan completed");
    expect(clean.body).toContain("no open issues found");
  });

  it("calls out a failed build gate", () => {
    const copy = completionCopy("api", { ...none, mediumCount: 4 }, true);
    expect(copy.title).toBe("Build gate failed: api");
    expect(copy.body).toBe("Scan of api finished with 4 medium. The build gate did not pass.");
  });
});
