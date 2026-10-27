import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "crypto";
import {
  digestOf,
  inspectSigningKey,
  signWithKey,
  verifyWithKey,
} from "./code-signing";

function pemPair(type: "rsa" | "ec", opts: Record<string, unknown>) {
  return generateKeyPairSync(type as "rsa", {
    ...opts,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  } as never) as unknown as { privateKey: string; publicKey: string };
}

const rsa = pemPair("rsa", { modulusLength: 2048 });
const ec = pemPair("ec", { namedCurve: "prime256v1" });
const body = Buffer.from(JSON.stringify({ hello: "world" }));
const tampered = Buffer.from(JSON.stringify({ hello: "tampered" }));

describe("inspectSigningKey", () => {
  it("derives the public key and a stable fingerprint", () => {
    const info = inspectSigningKey(rsa.privateKey);
    expect(info.keyType).toBe("RSA");
    expect(info.bits).toBe(2048);
    expect(info.publicKeyPem.trim()).toBe(rsa.publicKey.trim());
    expect(info.fingerprint).toMatch(/^SHA256:[0-9a-f]{64}$/);
    expect(inspectSigningKey(rsa.privateKey).fingerprint).toBe(info.fingerprint);
  });

  it("accepts EC P-256 keys", () => {
    expect(inspectSigningKey(ec.privateKey)).toMatchObject({ keyType: "EC", bits: 256 });
  });

  it("rejects garbage, weak RSA, encrypted and unsupported keys", () => {
    expect(() => inspectSigningKey("not a key")).toThrow(/valid PEM/);
    const weak = pemPair("rsa", { modulusLength: 1024 });
    expect(() => inspectSigningKey(weak.privateKey)).toThrow(/2048/);
    const enc = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
        cipher: "aes-256-cbc",
        passphrase: "secret",
      },
    });
    expect(() => inspectSigningKey(enc.privateKey)).toThrow(/passphrase/);
    const ed = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    expect(() => inspectSigningKey(ed.privateKey)).toThrow(/Unsupported key type/);
  });
});

describe("signWithKey / verifyWithKey", () => {
  it.each([
    ["RSA", rsa, "sha256-rsa"],
    ["EC", ec, "sha256-ecdsa"],
  ] as const)("signs and verifies with %s", (_name, pair, algorithm) => {
    const bundle = signWithKey(body, pair.privateKey, "ci@pepper");
    expect(bundle.algorithm).toBe(algorithm);
    expect(bundle.artifactSha256).toBe(digestOf(body));
    expect(bundle.publicKeyPem?.trim()).toBe(pair.publicKey.trim());
    expect(bundle.keyFingerprint).toBe(inspectSigningKey(pair.privateKey).fingerprint);
    expect(verifyWithKey(body, bundle)).toBe(true);
    expect(verifyWithKey(body, bundle, pair.publicKey)).toBe(true);
    expect(verifyWithKey(tampered, bundle)).toBe(false);
  });

  it("fails against a different trusted key", () => {
    const bundle = signWithKey(body, rsa.privateKey);
    expect(verifyWithKey(body, bundle, ec.publicKey)).toBe(false);
  });

  it("fails when the bundle's public key was swapped for an attacker's", () => {
    const attacker = pemPair("rsa", { modulusLength: 2048 });
    const forged = signWithKey(tampered, attacker.privateKey);
    // Self-consistent, but not signed by the org's trusted key.
    expect(verifyWithKey(tampered, forged)).toBe(true);
    expect(verifyWithKey(tampered, forged, rsa.publicKey)).toBe(false);
  });
});
