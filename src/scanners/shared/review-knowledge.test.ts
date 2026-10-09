import { describe, it, expect, beforeEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { guideForFile, reviewKnowledgeFor, resetReviewKnowledgeCache } from "./review-knowledge";

const DIR = path.join(process.cwd(), "rules", "review-knowledge");

describe("review knowledge", () => {
  beforeEach(() => resetReviewKnowledgeCache());

  it("maps file extensions to language guides", () => {
    expect(guideForFile("crates/router/src/core/payments.rs")).toBe("rust");
    expect(guideForFile("src/app.tsx")).toBe("typescript");
    expect(guideForFile("Service.kt")).toBe("java");
    expect(guideForFile("lib/parser.hpp")).toBe("c");
    expect(guideForFile("README.md")).toBeUndefined();
  });

  it("every mapped guide file exists", () => {
    for (const f of ["universal", "rust", "typescript", "python", "go", "java", "php", "ruby", "csharp", "c", "swift"]) {
      expect(fs.existsSync(path.join(DIR, `${f}.md`)), f).toBe(true);
    }
  });

  it("includes universal plus one guide per distinct language", () => {
    const block = reviewKnowledgeFor(["a.rs", "b.rs", "c.py", undefined]);
    expect(block).toContain("REVIEW KNOWLEDGE");
    expect(block).toContain("Universal review checklist");
    expect(block).toContain("Rust security review guide");
    expect(block).toContain("Python security review guide");
    expect(block.match(/Rust security review guide/g)).toHaveLength(1);
  });

  it("still returns the universal checklist for unmapped files", () => {
    expect(reviewKnowledgeFor(["notes.txt"])).toContain("Universal review checklist");
  });
});
