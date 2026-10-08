import { describe, expect, it } from "vitest";
import { parseLlmJsonResponse, parseLlmJsonResponseDetailed, recoverCompleteFindings } from "./llm-gateway";

const full = JSON.stringify({
  findings: [
    { title: "Missing authentication on get_all_books", metadata: { route: "/books/v1", note: "uses } and ] in text" } },
    { title: "Unauthenticated database reset", metadata: { sink: "db.drop_all()" } },
  ],
});

describe("cut-off model answers", () => {
  it("parses a complete answer as before", () => {
    expect(parseLlmJsonResponseDetailed(full, { findings: [] })).toEqual({ value: JSON.parse(full), status: "ok" });
  });

  it("keeps every complete finding when the cut falls inside a later finding's nested object", () => {
    const cut = full.slice(0, full.indexOf("db.drop_all") + 4); // inside the second finding's metadata
    const r = parseLlmJsonResponseDetailed<{ findings: Array<{ title: string }> }>(cut, { findings: [] });
    expect(r.status).toBe("recovered");
    expect(r.value.findings.map((f) => f.title)).toEqual(["Missing authentication on get_all_books"]);
    // The plain parser used everywhere else recovers the same way.
    expect(parseLlmJsonResponse<{ findings: unknown[] }>(cut, { findings: [] }).findings).toHaveLength(1);
  });

  it("is not fooled by braces or brackets inside strings", () => {
    const cut = full.slice(0, full.indexOf("Unauthenticated"));
    expect(recoverCompleteFindings(cut)).toEqual([JSON.parse(full).findings[0]]);
  });

  it("reports failure when nothing complete is left", () => {
    const cut = full.slice(0, 40);
    expect(parseLlmJsonResponseDetailed(cut, { findings: [] })).toEqual({ value: { findings: [] }, status: "failed" });
  });
});
