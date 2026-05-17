import { createHash, createSign, createVerify } from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";

const execFileP = promisify(execFile);

export interface SignatureBundle {
  algorithm: "sha256-rsa" | "cosign";
  /** SHA-256 of the artifact bytes, hex-encoded. */
  artifactSha256: string;
  /** Signature payload. For cosign this is the base64 cosign signature. */
  signature: string;
  /** Identity that signed (for keyless cosign this is the OIDC identity). */
  identity?: string;
  /** Public key in PEM, when used in key-based mode. */
  publicKeyPem?: string;
  signedAt: string;
}

/**
 * Sign an artifact in-process using a PEM RSA private key. Used for
 * environments where cosign is not installed (mostly tests/CI).
 */
export function signWithRsaKey(
  artifact: Buffer | string,
  privateKeyPem: string,
  publicKeyPem?: string,
  identity?: string,
): SignatureBundle {
  const data = typeof artifact === "string" ? Buffer.from(artifact) : artifact;
  const sha = createHash("sha256").update(data).digest("hex");
  const signer = createSign("RSA-SHA256");
  signer.update(data);
  signer.end();
  const sig = signer.sign(privateKeyPem).toString("base64");
  return {
    algorithm: "sha256-rsa",
    artifactSha256: sha,
    signature: sig,
    identity,
    publicKeyPem,
    signedAt: new Date().toISOString(),
  };
}

export function verifyWithRsaKey(
  artifact: Buffer | string,
  bundle: SignatureBundle,
): boolean {
  if (bundle.algorithm !== "sha256-rsa" || !bundle.publicKeyPem) return false;
  const data = typeof artifact === "string" ? Buffer.from(artifact) : artifact;
  const verifier = createVerify("RSA-SHA256");
  verifier.update(data);
  verifier.end();
  return verifier.verify(
    bundle.publicKeyPem,
    Buffer.from(bundle.signature, "base64"),
  );
}

async function cosignAvailable(): Promise<boolean> {
  try {
    await execFileP("cosign", ["version"], { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Sign an artifact with cosign in keyless mode (sigstore Fulcio + Rekor).
 * Returns null if cosign is unavailable so callers can fall back to RSA.
 *
 * The artifact must already be uploaded as an OCI blob OR represented by
 * its sha256 digest. For Pepper SBOM / SARIF artifacts we sign the blob
 * digest, which is sufficient for in-toto attestation use cases.
 */
export async function signWithCosignKeyless(
  artifactDigest: string,
  identity?: string,
): Promise<SignatureBundle | null> {
  if (!(await cosignAvailable())) return null;
  try {
    const { stdout } = await execFileP(
      "cosign",
      [
        "sign-blob",
        "--yes",
        "--output-signature",
        "-",
        "--bundle",
        "-",
        `sha256:${artifactDigest}`,
      ],
      {
        timeout: 60_000,
        env: { ...process.env, COSIGN_EXPERIMENTAL: "1" },
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    return {
      algorithm: "cosign",
      artifactSha256: artifactDigest,
      signature: stdout.trim(),
      identity,
      signedAt: new Date().toISOString(),
    };
  } catch {
    return null;
  }
}

export function digestOf(artifact: Buffer | string): string {
  const data = typeof artifact === "string" ? Buffer.from(artifact) : artifact;
  return createHash("sha256").update(data).digest("hex");
}
