import { describe, it, expect } from "vitest";
import {
  evaluateLicenseExpression,
  evaluateLicenses,
  parseSpdxExpression,
  shouldReport,
  type LicensePolicy,
} from "./license-policy";

const policy: LicensePolicy = {
  deny: ["AGPL-*", "GPL-*", "SSPL-*", "BUSL-*", "Commons-Clause"],
  warn: ["LGPL-*", "MPL-*", "EPL-*"],
  flagUnknown: false,
};

const verdict = (expr: string) =>
  evaluateLicenseExpression(expr, policy).verdict;

describe("SPDX expression parsing", () => {
  it("parses a bare license ID", () => {
    expect(parseSpdxExpression("MIT")).toEqual({ kind: "license", id: "MIT" });
  });

  it("parses OR and AND into distinct nodes", () => {
    expect(parseSpdxExpression("MIT OR Apache-2.0").kind).toBe("or");
    expect(parseSpdxExpression("MIT AND CC0-1.0").kind).toBe("and");
  });

  it("parses parenthesised sub-expressions", () => {
    const tree = parseSpdxExpression("(MIT OR Apache-2.0) AND CC0-1.0");
    expect(tree.kind).toBe("and");
  });

  it("ignores WITH exceptions, keeping the base license", () => {
    expect(parseSpdxExpression("Apache-2.0 WITH LLVM-exception")).toEqual({
      kind: "license",
      id: "Apache-2.0",
    });
  });
});

describe("license policy — permissive licenses", () => {
  it("allows common permissive licenses", () => {
    expect(verdict("MIT")).toBe("allowed");
    expect(verdict("Apache-2.0")).toBe("allowed");
    expect(verdict("BSD-3-Clause")).toBe("allowed");
    expect(verdict("0BSD")).toBe("allowed");
  });
});

describe("license policy — OR semantics", () => {
  // The critical false-positive case: substring matching on "GPL" would flag
  // this, but the consumer may simply take the BSD branch.
  it("does not deny a dual license where one branch is allowed", () => {
    expect(verdict("BSD-3-Clause OR GPL-2.0")).toBe("allowed");
    expect(verdict("GPL-2.0 OR MIT")).toBe("allowed");
  });

  it("denies only when every OR branch is denied", () => {
    expect(verdict("GPL-2.0 OR AGPL-3.0")).toBe("denied");
  });

  it("prefers an allowed branch over a warn branch", () => {
    expect(verdict("MIT OR LGPL-3.0")).toBe("allowed");
  });

  it("falls back to warn when no branch is fully allowed", () => {
    expect(verdict("LGPL-3.0 OR GPL-3.0")).toBe("warn");
  });

  it("handles the real-world cargo dual-license form", () => {
    expect(verdict("Apache-2.0 OR MIT")).toBe("allowed");
  });
});

describe("license policy — AND semantics", () => {
  it("denies when any AND term is denied, since all obligations bind", () => {
    expect(verdict("MIT AND GPL-3.0")).toBe("denied");
  });

  it("warns when an AND term is weak copyleft", () => {
    expect(verdict("MIT AND MPL-2.0")).toBe("warn");
  });

  it("allows when every AND term is allowed", () => {
    expect(verdict("MIT AND CC0-1.0")).toBe("allowed");
  });

  it("evaluates nested expressions correctly", () => {
    // The OR resolves to allowed (MIT), so the AND is allowed AND allowed.
    expect(verdict("(MIT OR GPL-3.0) AND Apache-2.0")).toBe("allowed");
    // Here the AND contains a denied term regardless of the OR branch chosen.
    expect(verdict("(MIT OR Apache-2.0) AND AGPL-3.0")).toBe("denied");
  });
});

describe("license policy — pattern matching", () => {
  it("matches SPDX -only and -or-later variants of a bare pattern", () => {
    const p: LicensePolicy = { deny: ["GPL-2.0"], warn: [], flagUnknown: false };
    expect(evaluateLicenseExpression("GPL-2.0-only", p).verdict).toBe("denied");
    expect(evaluateLicenseExpression("GPL-2.0-or-later", p).verdict).toBe("denied");
    expect(evaluateLicenseExpression("GPL-2.0+", p).verdict).toBe("denied");
  });

  it("does not let a GPL wildcard catch LGPL", () => {
    // LGPL is weak copyleft and must not be swept up by "GPL-*".
    expect(verdict("LGPL-3.0")).toBe("warn");
    expect(verdict("LGPL-2.1-only")).toBe("warn");
  });

  it("does not let a GPL wildcard catch AGPL via prefix confusion", () => {
    const p: LicensePolicy = { deny: ["GPL-*"], warn: [], flagUnknown: false };
    // AGPL does not start with "GPL-", so it needs its own rule.
    expect(evaluateLicenseExpression("AGPL-3.0", p).verdict).toBe("allowed");
  });

  it("is case insensitive", () => {
    expect(verdict("gpl-3.0")).toBe("denied");
    expect(verdict("mit")).toBe("allowed");
  });

  it("reports which pattern and license triggered the verdict", () => {
    const result = evaluateLicenseExpression("MIT AND GPL-3.0", policy);
    expect(result.verdict).toBe("denied");
    expect(result.matchedPattern).toBe("GPL-*");
    expect(result.matchedLicense).toBe("GPL-3.0");
  });

  it("omits the matched license when the verdict is allowed", () => {
    expect(evaluateLicenseExpression("MIT", policy).matchedLicense).toBeUndefined();
  });
});

describe("license policy — unknown licenses", () => {
  it("treats the deps.dev non-standard marker as unknown", () => {
    expect(verdict("non-standard")).toBe("unknown");
  });

  it("treats NOASSERTION and empty input as unknown", () => {
    expect(verdict("NOASSERTION")).toBe("unknown");
    expect(evaluateLicenseExpression("", policy).verdict).toBe("unknown");
  });

  it("does not report unknown licenses by default", () => {
    expect(shouldReport("unknown", policy)).toBe(false);
  });

  it("reports unknown licenses when the policy opts in", () => {
    expect(shouldReport("unknown", { ...policy, flagUnknown: true })).toBe(true);
  });

  it("always reports denied and never reports allowed", () => {
    expect(shouldReport("denied", policy)).toBe(true);
    expect(shouldReport("warn", policy)).toBe(true);
    expect(shouldReport("allowed", policy)).toBe(false);
  });
});

describe("evaluateLicenses (registry array form)", () => {
  it("returns unknown for a missing or empty list", () => {
    expect(evaluateLicenses(undefined, policy).verdict).toBe("unknown");
    expect(evaluateLicenses([], policy).verdict).toBe("unknown");
  });

  it("evaluates a single expression entry", () => {
    expect(evaluateLicenses(["Apache-2.0 OR MIT"], policy).verdict).toBe("allowed");
  });

  it("treats multiple array entries as alternatives", () => {
    expect(evaluateLicenses(["GPL-3.0", "MIT"], policy).verdict).toBe("allowed");
  });

  it("denies when every array entry is denied", () => {
    expect(evaluateLicenses(["GPL-3.0", "AGPL-3.0"], policy).verdict).toBe("denied");
  });

  it("preserves the declared expression for reporting", () => {
    expect(evaluateLicenses(["GPL-3.0", "AGPL-3.0"], policy).expression).toBe(
      "GPL-3.0, AGPL-3.0",
    );
  });
});
