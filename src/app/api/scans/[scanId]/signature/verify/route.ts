import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getActiveOrgId } from "@/lib/auth-guard";
import { downloadObject } from "@/lib/minio";
import { decryptSecret } from "@/lib/token-encryption";
import {
  digestOf,
  inspectSigningKey,
  verifyWithKey,
  type SignatureBundle,
} from "@/lib/code-signing";

/** Signature-bundle label → the artifact it signs. */
const SIGNED_ARTIFACTS = {
  cyclonedx: "SBOM_CYCLONEDX",
  spdx: "SBOM_SPDX",
  openvex: "VEX_OPENVEX",
  "cyclonedx-vex": "VEX_CYCLONEDX",
} as const;

export interface ArtifactVerification {
  label: string;
  algorithm: SignatureBundle["algorithm"];
  signedAt: string;
  /** Stored artifact bytes still hash to the signed digest. */
  digestMatches: boolean;
  /** Key mode: signature checks out against the org's current public key. */
  signatureValid: boolean | null;
  /** Key mode: the signing key is the org's current key. */
  signedByCurrentKey: boolean | null;
  keyFingerprint?: string;
}

/**
 * Re-check a scan's signatures against its stored artifacts and the org's
 * current signing key. Keyless (cosign) bundles get the digest check only;
 * their certificate chain is verified with `cosign verify-blob`.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;
  const orgId = await getActiveOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }
  const { scanId } = await params;

  const artifacts = await prisma.scanArtifact.findMany({
    where: { scanId, scan: { project: { organizationId: orgId } } },
    select: { type: true, objectKey: true },
  });
  const sigArtifact = artifacts.find((a) => a.type === "SIGNATURE");
  if (!sigArtifact) {
    return NextResponse.json({ error: "This scan has no signatures" }, { status: 404 });
  }

  const settings = await prisma.orgSettings.findUnique({
    where: { organizationId: orgId },
    select: { codeSigningKeyEnc: true },
  });
  let trustedKey: { publicKeyPem: string; fingerprint: string } | null = null;
  if (settings?.codeSigningKeyEnc) {
    try {
      trustedKey = inspectSigningKey(decryptSecret(settings.codeSigningKeyEnc));
    } catch {
      trustedKey = null;
    }
  }

  let bundles: Record<string, SignatureBundle>;
  try {
    bundles = JSON.parse((await downloadObject(sigArtifact.objectKey)).toString("utf8"));
  } catch {
    return NextResponse.json({ error: "Failed to read signatures" }, { status: 500 });
  }

  const results: ArtifactVerification[] = [];
  for (const [label, bundle] of Object.entries(bundles)) {
    const type = SIGNED_ARTIFACTS[label as keyof typeof SIGNED_ARTIFACTS];
    const artifact = type ? artifacts.find((a) => a.type === type) : undefined;
    let body: Buffer | null = null;
    if (artifact) {
      try {
        body = await downloadObject(artifact.objectKey);
      } catch {
        body = null;
      }
    }
    const keyMode = bundle.algorithm !== "cosign";
    results.push({
      label,
      algorithm: bundle.algorithm,
      signedAt: bundle.signedAt,
      digestMatches: body !== null && digestOf(body) === bundle.artifactSha256,
      signatureValid:
        keyMode && body !== null && trustedKey
          ? verifyWithKey(body, bundle, trustedKey.publicKeyPem)
          : keyMode
            ? false
            : null,
      signedByCurrentKey: keyMode
        ? !!trustedKey && bundle.keyFingerprint === trustedKey.fingerprint
        : null,
      keyFingerprint: bundle.keyFingerprint,
    });
  }

  const verified =
    results.length > 0 &&
    results.every((r) => r.digestMatches && r.signatureValid !== false);
  return NextResponse.json({ verified, results });
}
