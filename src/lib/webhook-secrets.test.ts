import { describe, it, expect } from "vitest";
import crypto from "crypto";
import {
  verifyGithubSignature,
  verifyGitlabToken,
  verifyBitbucketSignature,
  verifyAzureDevOpsBasicAuth,
} from "./webhook-secrets";

describe("webhook-secrets verification", () => {
  const secret = "test-webhook-secret";

  it("accepts valid GitHub sha256 signature", () => {
    const body = '{"ref":"refs/heads/main"}';
    const sig = `sha256=${crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("hex")}`;
    expect(verifyGithubSignature(body, sig, [secret])).toBe(true);
    expect(verifyGithubSignature(body, "sha256=bad", [secret])).toBe(false);
  });

  it("accepts GitLab token match", () => {
    expect(verifyGitlabToken(secret, [secret])).toBe(true);
    expect(verifyGitlabToken("wrong", [secret])).toBe(false);
    expect(verifyGitlabToken(null, [])).toBe(true);
  });

  it("accepts Bitbucket HMAC signature", () => {
    const body = "{}";
    const sig = `sha256=${crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("hex")}`;
    expect(verifyBitbucketSignature(body, sig, [secret])).toBe(true);
  });

  it("accepts Azure DevOps basic auth password", () => {
    const auth = `Basic ${Buffer.from(`:${secret}`).toString("base64")}`;
    expect(verifyAzureDevOpsBasicAuth(auth, [secret])).toBe(true);
    expect(verifyAzureDevOpsBasicAuth("Basic xxx", [secret])).toBe(false);
  });
});
