import { describe, it, expect } from "vitest";
import { groupFindingsBySection, FINDING_SECTIONS } from "./finding-sections";

const f = (scanner: string) => ({ scanner });

/**
 * The bug: tab counts were derived from the loaded findings, and any section with
 * none loaded was dropped. The API returns at most 500 findings, so on a scan
 * with 611 — 403 of them critical, with severity sorting — the lower-severity SCA
 * findings fell outside the page and their tab disappeared entirely. The user saw
 * "Findings 500 of 611" with no SCA tab at all.
 */
describe("section counts come from the scan, not the page", () => {
  it("keeps a section whose findings are all beyond the page limit", () => {
    const loaded = [f("SAST_LLM"), f("SAST_LLM")];
    const counts = { SAST_LLM: 206, SCA: 3 };

    const sections = groupFindingsBySection(loaded, counts);
    const sca = sections.find((s) => s.id === "SCA");

    expect(sca).toBeDefined();
    expect(sca!.total).toBe(3);
    expect(sca!.findings).toHaveLength(0);
  });

  it("reports the scan total, not the number loaded", () => {
    const sections = groupFindingsBySection([f("SAST_LLM")], { SAST_LLM: 206 });
    expect(sections.find((s) => s.id === "SAST")!.total).toBe(206);
  });

  it("still drops a section the scan genuinely has nothing for", () => {
    const sections = groupFindingsBySection([f("SAST_LLM")], { SAST_LLM: 1 });
    expect(sections.find((s) => s.id === "SCA")).toBeUndefined();
    expect(sections.find((s) => s.id === "CONTAINER")).toBeUndefined();
  });

  it("sums scanners that share a section", () => {
    // Secrets has both a pattern and an AI scanner behind one tab.
    const secretsSection = FINDING_SECTIONS.find((s) => s.id === "SECRETS")!;
    const counts: Record<string, number> = {};
    for (const scanner of secretsSection.scanners) counts[scanner] = 5;

    const sections = groupFindingsBySection([], counts);
    expect(sections.find((s) => s.id === "SECRETS")!.total).toBe(
      secretsSection.scanners.length * 5,
    );
  });

  it("groups scanners with no dedicated section under Other", () => {
    const sections = groupFindingsBySection([], { SOMETHING_NEW: 7 });
    const other = sections.find((s) => s.id === "OTHER");
    expect(other!.total).toBe(7);
  });

  it("does not double count an ungrouped scanner into a section", () => {
    const sections = groupFindingsBySection([], { SCA: 2, SOMETHING_NEW: 7 });
    expect(sections.find((s) => s.id === "SCA")!.total).toBe(2);
    expect(sections.find((s) => s.id === "OTHER")!.total).toBe(7);
  });

  it("falls back to the loaded count when the API sent no totals", () => {
    // Older responses, or a request that failed to include the aggregate.
    const sections = groupFindingsBySection([f("SCA"), f("SCA")]);
    expect(sections.find((s) => s.id === "SCA")!.total).toBe(2);
  });

  it("returns no sections for an empty scan", () => {
    expect(groupFindingsBySection([], {})).toEqual([]);
  });

  it("preserves the full finding objects it was given", () => {
    // The page passes these straight to the findings table.
    const loaded = [{ scanner: "SCA", id: "abc", severity: "HIGH" }];
    const sections = groupFindingsBySection(loaded, { SCA: 1 });
    expect(sections.find((s) => s.id === "SCA")!.findings[0].id).toBe("abc");
  });

  it("reproduces the reported scan without losing a category", () => {
    // 611 findings, 500 loaded, severity-sorted so the page is all critical/high.
    const counts = {
      SAST_LLM: 206,
      SECRETS_LLM: 207,
      MALICIOUS_PKG: 2,
      IAC: 23,
      CONTAINER: 4,
      ZERO_DAY: 58,
      SCA: 3,
    };
    const loaded = Array.from({ length: 500 }, () => f("SAST_LLM"));

    const sections = groupFindingsBySection(loaded, counts);
    const ids = sections.map((s) => s.id);

    // Every category the scan produced is present, SCA included.
    expect(ids).toContain("SCA");
    // And every finding is accounted for exactly once across the sections.
    expect(sections.reduce((sum, s) => sum + s.total, 0)).toBe(
      Object.values(counts).reduce((a, b) => a + b, 0),
    );
  });
});

describe("every scanner has a home", () => {
  const ALL_SCANNERS = [
    "SAST_PATTERN",
    "SAST_LLM",
    "SCA",
    "SECRETS_PATTERN",
    "SECRETS_LLM",
    "IAC",
    "MALICIOUS_PKG",
    "ZERO_DAY",
    "CONTAINER",
    "K8S",
  ];

  it("maps every Scanner enum value to a dedicated tab", () => {
    const mapped = new Set(FINDING_SECTIONS.flatMap((s) => s.scanners));
    for (const scanner of ALL_SCANNERS) {
      expect(mapped.has(scanner)).toBe(true);
    }
  });

  it("puts both secret scanners in the Secrets tab", () => {
    // SECRETS_PATTERN was previously unmapped and fell into Other, a
    // high-volume scanner that crowded every other category off the page.
    const sections = groupFindingsBySection([], {
      SECRETS_LLM: 9,
      SECRETS_PATTERN: 300,
    });
    expect(sections.find((s) => s.id === "SECRETS")!.total).toBe(309);
    expect(sections.find((s) => s.id === "OTHER")).toBeUndefined();
  });

  it("gives Kubernetes findings their own tab", () => {
    const sections = groupFindingsBySection([], { K8S: 5 });
    expect(sections.find((s) => s.id === "K8S")!.total).toBe(5);
    expect(sections.find((s) => s.id === "OTHER")).toBeUndefined();
  });

  it("leaves Other empty for a normal scan", () => {
    const counts: Record<string, number> = {};
    for (const scanner of ALL_SCANNERS) counts[scanner] = 3;
    const sections = groupFindingsBySection([], counts);
    expect(sections.find((s) => s.id === "OTHER")).toBeUndefined();
  });
})
