import { describe, it, expect } from "vitest";
import { prioritizeFiles, selectZeroDayFiles } from "./file-prioritizer";

function priorityOf(files: string[], target: string) {
  return prioritizeFiles(files).find((f) => f.path === target)?.priority;
}

describe("zero-day file prioritizer", () => {
  it("ranks auth/payment files as critical", () => {
    expect(priorityOf(["src/auth/login.ts"], "src/auth/login.ts")).toBe(
      "critical",
    );
    expect(priorityOf(["src/payment.ts"], "src/payment.ts")).toBe("critical");
  });

  it("prioritizes native / memory-unsafe source files (memory-safety targets)", () => {
    // C/C++/ObjC sources and native binding dirs must be analyzed, not left as
    // 'normal' where the budget can drop them.
    for (const f of [
      "src/parser.c",
      "lib/buffer.cpp",
      "include/frame.h",
      "native/binding.cc",
    ]) {
      expect(priorityOf([f], f)).not.toBe("normal");
    }
  });

  it("prioritizes unsafe-deserialization signals (gadget-chain targets)", () => {
    for (const f of [
      "app/jobs/unpickle_task.py",
      "src/marshal-loader.rb",
      "lib/unserialize.php",
    ]) {
      expect(priorityOf([f], f)).not.toBe("normal");
    }
  });

  it("leaves plain utility files as normal", () => {
    expect(priorityOf(["src/format-date.ts"], "src/format-date.ts")).toBe(
      "normal",
    );
  });

  it("keeps a plain README out of the priority slice", () => {
    const selected = selectZeroDayFiles(
      ["src/auth.ts", "src/parser.c", "docs/README.md"],
      10,
      10,
    );
    // All still selected within budget, but priority ones come first.
    expect(selected.indexOf("src/parser.c")).toBeLessThan(
      selected.indexOf("docs/README.md"),
    );
  });
});
