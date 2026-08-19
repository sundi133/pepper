import { describe, it, expect } from "vitest";
import { SYSTEM_PROMPT } from "./llm-analyzer";

/**
 * Coverage guard: SYSTEM_PROMPT must explicitly name every high-signal
 * vulnerability class the scanner is expected to surface for the Broken
 * Crystals benchmark app. Phrases are matched whitespace-tolerantly so that
 * re-wrapping prompt text does not fail these assertions.
 */
describe("SYSTEM_PROMPT detection coverage", () => {
  it("covers JWT rogue-key header injection and weak secrets", () => {
    expect(SYSTEM_PROMPT).toMatch(/x5u|jku|jwk/i);
    expect(SYSTEM_PROMPT).toMatch(/invalid\s+signature/i);
    expect(SYSTEM_PROMPT).toMatch(/weak\/brute-forceable\s+HS256/i);
  });

  it("covers raw template interpolation sinks", () => {
    expect(SYSTEM_PROMPT).toMatch(/<%-\s*%>/);
    expect(SYSTEM_PROMPT).toMatch(/\{\{\{\s*\}\}\}/);
    expect(SYSTEM_PROMPT).toMatch(/\|safe|mark_safe|escape=False/i);
  });

  it("covers CSS/iframe/attribute injection in rendered HTML", () => {
    expect(SYSTEM_PROMPT).toMatch(/CSS\/style\s+injection/i);
    expect(SYSTEM_PROMPT).toMatch(/iframe\s+injection/i);
    expect(SYSTEM_PROMPT).toMatch(/attribute\s+injection/i);
  });

  it("covers open redirect as a first-class class", () => {
    expect(SYSTEM_PROMPT).toMatch(/Open\s+redirect\s+\(CWE-601\)/i);
    expect(SYSTEM_PROMPT).toMatch(/res\.redirect|window\.location/i);
  });

  it("covers email/header injection", () => {
    expect(SYSTEM_PROMPT).toMatch(/Email\/header\s+injection\s+\(CWE-93\/CWE-94\)/i);
    expect(SYSTEM_PROMPT).toMatch(/Cc,?\s*Bcc/i);
  });

  it("covers full path disclosure", () => {
    expect(SYSTEM_PROMPT).toMatch(/Full\s+path\s+disclosure\s+\(CWE-209\)/i);
    expect(SYSTEM_PROMPT).toMatch(/absolute\s+filesystem\s+paths/i);
  });

  it("covers default/weak credentials", () => {
    expect(SYSTEM_PROMPT).toMatch(/Default\/weak\s+credentials/i);
    expect(SYSTEM_PROMPT).toMatch(/admin\/admin/i);
  });

  it("covers config/secret-exposing endpoints", () => {
    expect(SYSTEM_PROMPT).toMatch(/Config\/secret-exposing\s+endpoints/i);
    expect(SYSTEM_PROMPT).toMatch(/\/api\/config|connection\s+strings/i);
  });

  it("covers web-server directory listing and method exposure", () => {
    expect(SYSTEM_PROMPT).toMatch(/autoindex\s+on/i);
    expect(SYSTEM_PROMPT).toMatch(/dav_methods/i);
  });
});
