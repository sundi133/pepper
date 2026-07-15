/**
 * Data-integrity guard for the bundled compliance framework catalogs.
 *
 * Catches the kinds of mistakes hand-authored JSON is prone to: malformed CWE
 * ids, invalid scanner names in `appliesTo`, bad coverage values, duplicate
 * control ids, and controls that claim a mapping but supply none. Runs against
 * every framework returned by loadAllFrameworks() so new framework files are
 * covered automatically.
 */
import { describe, it, expect } from "vitest";
import { loadAllFrameworks } from "./pdf-parser";

// Mirror of the Prisma `Scanner` enum (prisma/schema.prisma). Kept in sync
// manually; the test below fails loudly if a framework references anything else.
const VALID_SCANNERS = new Set([
  "SAST_PATTERN",
  "SAST_LLM",
  "SCA",
  "SECRETS_PATTERN",
  "SECRETS_LLM",
  "IAC",
  "MALICIOUS_PKG",
  "ZERO_DAY",
  "CONTAINER",
]);

const VALID_COVERAGE = new Set(["assessable", "partial", "not-assessable"]);
const CWE_RE = /^CWE-\d+$/;

const frameworks = loadAllFrameworks();

describe("compliance framework data integrity", () => {
  it("loads at least the target frameworks", () => {
    expect(frameworks.length).toBeGreaterThanOrEqual(11);
  });

  for (const fw of frameworks) {
    describe(fw.name, () => {
      it("has a non-empty control set and unique control ids", () => {
        expect(fw.controls.length).toBeGreaterThan(0);
        const ids = fw.controls.map((c) => c.controlId);
        const dupes = ids.filter((id, i) => ids.indexOf(id) !== i);
        expect(dupes, `duplicate control ids: ${dupes.join(", ")}`).toEqual([]);
      });

      it("every control has an id and a title", () => {
        for (const c of fw.controls) {
          expect(c.controlId, `missing controlId in ${fw.name}`).toBeTruthy();
          expect(c.title, `missing title for ${c.controlId}`).toBeTruthy();
        }
      });

      it("cweMapping entries are well-formed CWE ids", () => {
        for (const c of fw.controls) {
          for (const cwe of c.cweMapping || []) {
            expect(
              CWE_RE.test(cwe),
              `${fw.name} ${c.controlId}: malformed CWE "${cwe}"`,
            ).toBe(true);
          }
        }
      });

      it("appliesTo scanners are valid Scanner enum values", () => {
        for (const c of fw.controls) {
          for (const s of c.appliesTo?.scanners || []) {
            expect(
              VALID_SCANNERS.has(s),
              `${fw.name} ${c.controlId}: invalid scanner "${s}"`,
            ).toBe(true);
          }
        }
      });

      it("coverage values are valid when set", () => {
        for (const c of fw.controls) {
          if (c.coverage !== undefined) {
            expect(
              VALID_COVERAGE.has(c.coverage),
              `${fw.name} ${c.controlId}: invalid coverage "${c.coverage}"`,
            ).toBe(true);
          }
        }
      });

      it("assessable controls actually carry a mapping", () => {
        // A control marked assessable must have either a CWE crosswalk or an
        // activity-level rule — otherwise nothing can ever map to it.
        for (const c of fw.controls) {
          if (c.coverage === "assessable") {
            const hasMapping =
              (c.cweMapping && c.cweMapping.length > 0) || !!c.appliesTo;
            expect(
              hasMapping,
              `${fw.name} ${c.controlId}: marked assessable but has no cweMapping/appliesTo`,
            ).toBe(true);
          }
        }
      });
    });
  }
});
