import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "crypto";
import { signWithRsaKey, verifyWithRsaKey, digestOf } from "./code-signing";

describe("code-signing RSA fallback", () => {
  it("signs and verifies an artifact", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const body = Buffer.from(JSON.stringify({ hello: "world" }));
    const bundle = signWithRsaKey(body, privateKey, publicKey, "ci@pepper");
    expect(bundle.algorithm).toBe("sha256-rsa");
    expect(bundle.artifactSha256).toBe(digestOf(body));
    expect(verifyWithRsaKey(body, bundle)).toBe(true);
    // Tampering breaks verification
    const tampered = Buffer.from(JSON.stringify({ hello: "tampered" }));
    expect(verifyWithRsaKey(tampered, bundle)).toBe(false);
  });
});
