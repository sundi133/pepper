import { describe, it, expect } from "vitest";
import {
  getOwasp2024Category,
  getOwaspApiCategory,
  getOwaspLlmCategory,
  getOwasp2024Code,
  getCweCategory,
} from "./owasp-mapper";

describe("getOwaspLlmCategory", () => {
  it("maps CWEs to the OWASP LLM Top 10 (2025) categories", () => {
    expect(getOwaspLlmCategory("CWE-94")).toBe("LLM01:2025 Prompt Injection");
    expect(getOwaspLlmCategory("CWE-1427")).toBe("LLM01:2025 Prompt Injection");
    expect(getOwaspLlmCategory("CWE-200")).toBe(
      "LLM02:2025 Sensitive Information Disclosure",
    );
    expect(getOwaspLlmCategory("CWE-1104")).toBe("LLM03:2025 Supply Chain");
    expect(getOwaspLlmCategory("CWE-502")).toBe(
      "LLM04:2025 Data and Model Poisoning",
    );
    expect(getOwaspLlmCategory("CWE-79")).toBe(
      "LLM05:2025 Improper Output Handling",
    );
    expect(getOwaspLlmCategory("CWE-284")).toBe("LLM06:2025 Excessive Agency");
    expect(getOwaspLlmCategory("CWE-770")).toBe(
      "LLM10:2025 Unbounded Consumption",
    );
  });

  it("returns null for CWEs with no LLM-relevant classification", () => {
    expect(getOwaspLlmCategory("CWE-327")).toBeNull(); // crypto — web only
    expect(getOwaspLlmCategory("CWE-9999")).toBeNull(); // unknown
    expect(getOwaspLlmCategory(undefined)).toBeNull();
  });
});

describe("getOwasp2024Category", () => {
  it("keeps the web Top 10 mapping intact for newly added CWEs", () => {
    expect(getOwasp2024Category("CWE-284")).toBe(
      "A01:2021 Broken Access Control",
    );
    expect(getOwasp2024Category("CWE-78")).toBe("A03:2021 Injection");
    expect(getOwasp2024Category("CWE-770")).toBe(
      "A05:2021 Security Misconfiguration",
    );
    expect(getOwasp2024Category("CWE-693")).toBe(
      "A05:2021 Security Misconfiguration",
    );
    expect(getOwasp2024Category("CWE-548")).toBe(
      "A05:2021 Security Misconfiguration",
    );
  });

  it("returns null for unknown CWEs", () => {
    expect(getOwasp2024Category("CWE-9999")).toBeNull();
  });
});

describe("getOwaspApiCategory", () => {
  it("returns the API Top 10 category when present", () => {
    expect(getOwaspApiCategory("CWE-863")).toBe(
      "A01:2023 Broken Object Level Authorization",
    );
    expect(getOwaspApiCategory("CWE-284")).toBeNull();
  });
});

// Consolidated shared helpers (Phase 5): the PDF report and any other consumer
// use these instead of maintaining their own CWE tables.
describe("getOwasp2024Code", () => {
  it("returns the bare OWASP 2021 code, derived from the full category", () => {
    expect(getOwasp2024Code("CWE-89")).toBe("A03:2021");
    expect(getOwasp2024Code("CWE-918")).toBe("A10:2021");
    expect(getOwasp2024Code("CWE-9999")).toBeNull();
    expect(getOwasp2024Code(null)).toBeNull();
  });
  it("stays consistent with getOwasp2024Category", () => {
    const full = getOwasp2024Category("CWE-79");
    expect(full?.startsWith(getOwasp2024Code("CWE-79")!)).toBe(true);
  });
});

describe("getCweCategory", () => {
  it("returns a short human category label", () => {
    expect(getCweCategory("CWE-89")).toBe("Injection");
    expect(getCweCategory("CWE-79")).toBe("XSS");
    expect(getCweCategory("CWE-798")).toBe("Secrets");
    expect(getCweCategory("CWE-9999")).toBeNull();
    expect(getCweCategory(null)).toBeNull();
  });
});
