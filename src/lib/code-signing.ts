import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "crypto";
import { execFile } from "child_process";
import { mkdtemp, readFile, rm, writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { promisify } from "util";

const execFileP = promisify(execFile);

export type SigningAlgorithm = "sha256-rsa" | "sha256-ecdsa" | "cosign";

export interface SignatureBundle {
  algorithm: SigningAlgorithm;
  /** SHA-256 of the artifact bytes, hex-encoded. */
  artifactSha256: string;
  /** Base64 signature over the artifact bytes. */
  signature: string;
  /** Identity that signed (for keyless cosign this is the OIDC identity). */
  identity?: string;
  /** Public key in PEM, when used in key-based mode. */
  publicKeyPem?: string;
  /** SHA-256 fingerprint of the public key (key mode). */
  keyFingerprint?: string;
  /** Sigstore bundle (certificate + Rekor entry) for keyless mode. */
  cosignBundle?: unknown;
  signedAt: string;
}

export interface SigningKeyInfo {
  keyType: "RSA" | "EC";
  /** Key size in bits (RSA modulus or EC curve size). */
  bits: number;
  publicKeyPem: string;
  /** `SHA256:<hex>` of the DER-encoded public key. */
  fingerprint: string;
}

const MIN_RSA_BITS = 2048;

/** Fingerprint of a public key: SHA-256 over its DER (SPKI) encoding. */
export function publicKeyFingerprint(key: KeyObject | string): string {
  const obj = typeof key === "string" ? createPublicKey(key) : key;
  const der = obj.export({ type: "spki", format: "der" });
  return `SHA256:${createHash("sha256").update(der).digest("hex")}`;
}

/**
 * Validate a PEM private key for signing and derive its public half. Throws
 * an Error with a user-facing message when the key can't be used: encrypted,
 * malformed, an unsupported type, or an RSA key below 2048 bits.
 */
export function inspectSigningKey(privateKeyPem: string): SigningKeyInfo {
  // PKCS#8 ("BEGIN ENCRYPTED PRIVATE KEY") and legacy ("Proc-Type: 4,ENCRYPTED").
  if (/ENCRYPTED/.test(privateKeyPem)) {
    throw new Error("The private key is passphrase-protected; upload an unencrypted PEM key");
  }
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: privateKeyPem.trim(), format: "pem" });
  } catch {
    throw new Error("Not a valid PEM private key");
  }
  const type = key.asymmetricKeyType;
  const details = key.asymmetricKeyDetails ?? {};
  let keyType: SigningKeyInfo["keyType"];
  let bits: number;
  if (type === "rsa") {
    keyType = "RSA";
    bits = details.modulusLength ?? 0;
    if (bits < MIN_RSA_BITS) {
      throw new Error(`RSA keys must be at least ${MIN_RSA_BITS} bits (this one is ${bits})`);
    }
  } else if (type === "ec") {
    keyType = "EC";
    const curve = details.namedCurve ?? "";
    const curveBits: Record<string, number> = {
      prime256v1: 256,
      secp384r1: 384,
      secp521r1: 521,
    };
    bits = curveBits[curve] ?? 0;
    if (!bits) throw new Error(`Unsupported EC curve ${curve || "(unknown)"}; use P-256, P-384 or P-521`);
  } else {
    throw new Error(`Unsupported key type ${type ?? "(unknown)"}; use an RSA or EC (ECDSA) key`);
  }
  const publicKey = createPublicKey(key);
  return {
    keyType,
    bits,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    fingerprint: publicKeyFingerprint(publicKey),
  };
}

function toBuffer(artifact: Buffer | string): Buffer {
  return typeof artifact === "string" ? Buffer.from(artifact) : artifact;
}

/**
 * Sign an artifact in-process with a PEM RSA or EC private key. The bundle
 * carries the public key and its fingerprint, so anyone holding the org's
 * published key can verify it (`openssl dgst -sha256 -verify`).
 */
export function signWithKey(
  artifact: Buffer | string,
  privateKeyPem: string,
  identity?: string,
): SignatureBundle {
  const info = inspectSigningKey(privateKeyPem);
  const data = toBuffer(artifact);
  const sig = cryptoSign("sha256", data, privateKeyPem.trim()).toString("base64");
  return {
    algorithm: info.keyType === "RSA" ? "sha256-rsa" : "sha256-ecdsa",
    artifactSha256: digestOf(data),
    signature: sig,
    identity,
    publicKeyPem: info.publicKeyPem,
    keyFingerprint: info.fingerprint,
    signedAt: new Date().toISOString(),
  };
}

/**
 * Verify a key-based bundle against the artifact bytes. Pass the trusted
 * public key to check against; otherwise the bundle's own key is used, which
 * only proves the bytes are unchanged, not who signed them.
 */
export function verifyWithKey(
  artifact: Buffer | string,
  bundle: SignatureBundle,
  trustedPublicKeyPem?: string,
): boolean {
  if (bundle.algorithm !== "sha256-rsa" && bundle.algorithm !== "sha256-ecdsa") return false;
  const keyPem = trustedPublicKeyPem ?? bundle.publicKeyPem;
  if (!keyPem) return false;
  const data = toBuffer(artifact);
  if (digestOf(data) !== bundle.artifactSha256) return false;
  try {
    return cryptoVerify("sha256", data, keyPem, Buffer.from(bundle.signature, "base64"));
  } catch {
    return false;
  }
}

/** Identity token for keyless signing (CI-provided OIDC token). */
function sigstoreIdentityToken(): string | undefined {
  return process.env.SIGSTORE_ID_TOKEN?.trim() || undefined;
}

async function cosignInstalled(): Promise<boolean> {
  try {
    await execFileP("cosign", ["version"], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Whether keyless signing can run here: cosign installed and an OIDC identity
 * token in SIGSTORE_ID_TOKEN (a worker has no browser to log in with).
 */
export async function keylessSigningStatus(): Promise<{ available: boolean; reason?: string }> {
  if (!(await cosignInstalled())) {
    return { available: false, reason: "cosign is not installed on the scan worker" };
  }
  if (!sigstoreIdentityToken()) {
    return { available: false, reason: "SIGSTORE_ID_TOKEN is not set on the scan worker" };
  }
  return { available: true };
}

/**
 * Sign an artifact with cosign in keyless mode (sigstore Fulcio + Rekor).
 * Throws with the reason when signing can't run or cosign fails.
 */
export async function signWithCosignKeyless(
  artifact: Buffer | string,
  identity?: string,
): Promise<SignatureBundle> {
  const status = await keylessSigningStatus();
  if (!status.available) throw new Error(status.reason);
  const data = toBuffer(artifact);
  const dir = await mkdtemp(join(tmpdir(), "pepper-sign-"));
  try {
    const blobPath = join(dir, "artifact");
    const sigPath = join(dir, "artifact.sig");
    const bundlePath = join(dir, "artifact.bundle");
    await writeFile(blobPath, data);
    await execFileP(
      "cosign",
      [
        "sign-blob",
        "--yes",
        "--identity-token",
        sigstoreIdentityToken()!,
        "--output-signature",
        sigPath,
        "--bundle",
        bundlePath,
        blobPath,
      ],
      { timeout: 60_000, maxBuffer: 8 * 1024 * 1024 },
    );
    const [signature, bundleText] = await Promise.all([
      readFile(sigPath, "utf8"),
      readFile(bundlePath, "utf8"),
    ]);
    let cosignBundle: unknown = bundleText;
    try {
      cosignBundle = JSON.parse(bundleText);
    } catch {
      /* keep the raw text */
    }
    return {
      algorithm: "cosign",
      artifactSha256: digestOf(data),
      signature: signature.trim(),
      identity,
      cosignBundle,
      signedAt: new Date().toISOString(),
    };
  } catch (e) {
    const stderr = (e as { stderr?: string }).stderr?.trim();
    throw new Error(stderr ? `cosign failed: ${stderr.slice(0, 300)}` : (e as Error).message);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export function digestOf(artifact: Buffer | string): string {
  return createHash("sha256").update(toBuffer(artifact)).digest("hex");
}
