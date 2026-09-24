import { describe, expect, it } from "vitest";
import {
  anthropicAcceptsTemperature,
  anthropicResponseText,
  normalizeAnthropicBaseUrl,
} from "./llm-gateway";

describe("normalizeAnthropicBaseUrl", () => {
  it("strips a trailing /v1 so the SDK does not request /v1/v1/messages", () => {
    expect(normalizeAnthropicBaseUrl("https://api.anthropic.com/v1")).toBe(
      "https://api.anthropic.com",
    );
    expect(normalizeAnthropicBaseUrl("https://api.anthropic.com/v1/")).toBe(
      "https://api.anthropic.com",
    );
  });

  it("keeps an API root and proxy paths intact", () => {
    expect(normalizeAnthropicBaseUrl("https://api.anthropic.com")).toBe(
      "https://api.anthropic.com",
    );
    expect(normalizeAnthropicBaseUrl("https://gw.corp/anthropic/v1")).toBe(
      "https://gw.corp/anthropic",
    );
  });

  it("returns undefined for empty input (use the SDK default)", () => {
    expect(normalizeAnthropicBaseUrl("")).toBeUndefined();
    expect(normalizeAnthropicBaseUrl(undefined)).toBeUndefined();
    expect(normalizeAnthropicBaseUrl("  ")).toBeUndefined();
  });
});

describe("anthropicAcceptsTemperature", () => {
  it("omits sampling params for models that reject them", () => {
    for (const m of [
      "claude-opus-5",
      "claude-opus-5-5",
      "claude-sonnet-5",
      "claude-opus-4-8",
      "claude-opus-4-7",
      "claude-fable-5-1",
    ]) {
      expect(anthropicAcceptsTemperature(m), m).toBe(false);
    }
  });

  it("keeps sampling params for older models that accept them", () => {
    for (const m of [
      "claude-sonnet-4-6",
      "claude-opus-4-6",
      "claude-haiku-4-5",
      "claude-sonnet-4-5",
      "claude-sonnet-4-20250514",
      "claude-3-5-haiku-20241022",
    ]) {
      expect(anthropicAcceptsTemperature(m), m).toBe(true);
    }
  });
});

describe("anthropicResponseText", () => {
  it("skips a leading thinking block and joins text blocks", () => {
    expect(
      anthropicResponseText([
        { type: "thinking" },
        { type: "text", text: '{"findings":' },
        { type: "text", text: "[]}" },
      ]),
    ).toBe('{"findings":[]}');
  });

  it("returns an empty string when there is no text", () => {
    expect(anthropicResponseText([{ type: "thinking" }])).toBe("");
  });
});
