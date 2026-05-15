import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { decryptSecret, encryptSecret } from "./token-encryption";

describe("token-encryption", () => {
  const prev = process.env.NEXTAUTH_SECRET;

  beforeEach(() => {
    process.env.NEXTAUTH_SECRET = "test-secret-for-encryption";
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.NEXTAUTH_SECRET;
    else process.env.NEXTAUTH_SECRET = prev;
  });

  it("round-trips a secret", () => {
    const plain = "gho_testtoken123";
    const enc = encryptSecret(plain);
    expect(enc).not.toContain(plain);
    expect(decryptSecret(enc)).toBe(plain);
  });
});
