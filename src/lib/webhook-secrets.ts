import crypto from "crypto";
import { prisma } from "@/lib/prisma";
import { decryptSecret } from "@/lib/token-encryption";

export type WebhookProvider =
  | "github"
  | "gitlab"
  | "bitbucket"
  | "azure-devops";

const ENV_KEYS: Record<WebhookProvider, string> = {
  github: "GITHUB_WEBHOOK_SECRET",
  gitlab: "GITLAB_WEBHOOK_SECRET",
  bitbucket: "BITBUCKET_WEBHOOK_SECRET",
  "azure-devops": "AZURE_DEVOPS_WEBHOOK_SECRET",
};

const DB_FIELDS: Record<
  WebhookProvider,
  | "githubWebhookSecretEnc"
  | "gitlabWebhookSecretEnc"
  | "bitbucketWebhookSecretEnc"
  | "azureDevOpsWebhookSecretEnc"
> = {
  github: "githubWebhookSecretEnc",
  gitlab: "gitlabWebhookSecretEnc",
  bitbucket: "bitbucketWebhookSecretEnc",
  "azure-devops": "azureDevOpsWebhookSecretEnc",
};

function envSecret(provider: WebhookProvider): string | null {
  const v = process.env[ENV_KEYS[provider]]?.trim();
  return v || null;
}

/** All configured secrets for a provider (env first, then every org with a stored secret). */
export async function listWebhookSecrets(
  provider: WebhookProvider,
): Promise<string[]> {
  const out: string[] = [];
  const fromEnv = envSecret(provider);
  if (fromEnv) out.push(fromEnv);

  const field = DB_FIELDS[provider];
  const rows = await prisma.orgSettings.findMany({
    where: { [field]: { not: null } },
    select: { [field]: true },
  });

  for (const row of rows) {
    const enc = row[field] as string | null | undefined;
    if (!enc) continue;
    try {
      const plain = decryptSecret(enc);
      if (plain && !out.includes(plain)) out.push(plain);
    } catch {
      /* skip bad ciphertext */
    }
  }
  return out;
}

/** All configured secrets for a provider with their organization IDs. */
async function listWebhookSecretsWithOrgs(
  provider: WebhookProvider,
): Promise<Array<{ secret: string; organizationId: string | null }>> {
  const out: Array<{ secret: string; organizationId: string | null }> = [];
  const fromEnv = envSecret(provider);
  if (fromEnv) out.push({ secret: fromEnv, organizationId: null });

  const field = DB_FIELDS[provider];
  const rows = await prisma.orgSettings.findMany({
    where: { [field]: { not: null } },
    select: { [field]: true, organizationId: true },
  });

  for (const row of rows) {
    const enc = row[field] as string | null | undefined;
    if (!enc) continue;
    try {
      const plain = decryptSecret(enc);
      if (plain && !out.some((x) => x.secret === plain)) {
        out.push({ secret: plain, organizationId: row.organizationId });
      }
    } catch {
      /* skip bad ciphertext */
    }
  }
  return out;
}

/** Verify GitHub signature and return the organization ID if valid. */
async function verifyGithubSignatureWithOrg(
  body: string,
  signature: string | null,
): Promise<{ organizationId: string | null } | null> {
  if (!signature) return null;
  const secrets = await listWebhookSecretsWithOrgs("github");
  // Fail closed: no secret configured means no request can be authenticated,
  // never an implicit "allow" (see requireGithubWebhookAuth).
  if (secrets.length === 0) return null;
  for (const { secret, organizationId } of secrets) {
    const expected = `sha256=${crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("hex")}`;
    if (signature === expected) return { organizationId };
  }
  return null;
}

/** Verify Bitbucket signature and return the organization ID if valid. */
async function verifyBitbucketSignatureWithOrg(
  body: string,
  signature: string | null,
): Promise<{ organizationId: string | null } | null> {
  if (!signature) return null;
  const secrets = await listWebhookSecretsWithOrgs("bitbucket");
  // Fail closed: no secret configured means no request can be authenticated.
  if (secrets.length === 0) return null;
  for (const { secret, organizationId } of secrets) {
    const expected = `sha256=${crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("hex")}`;
    if (signature === expected) return { organizationId };
  }
  return null;
}

/** Verify Azure DevOps auth and return the organization ID if valid. */
async function verifyAzureDevOpsAuthWithOrg(
  authorization: string | null,
): Promise<{ organizationId: string | null } | null> {
  const token = parseBasicAuthPassword(authorization);
  if (!token) return null;
  const secrets = await listWebhookSecretsWithOrgs("azure-devops");
  // Fail closed: no secret configured means no request can be authenticated.
  if (secrets.length === 0) return null;
  for (const { secret, organizationId } of secrets) {
    if (token === secret) return { organizationId };
  }
  return null;
}

export function verifyGithubSignature(
  body: string,
  signature: string | null,
  secrets: string[],
): boolean {
  if (!signature || secrets.length === 0) return secrets.length === 0;
  return secrets.some((secret) => {
    const expected = `sha256=${crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("hex")}`;
    return signature === expected;
  });
}

export function verifyGitlabToken(
  token: string | null,
  secrets: string[],
): boolean {
  if (secrets.length === 0) return true;
  if (!token) return false;
  return secrets.includes(token);
}

export function verifyBitbucketSignature(
  body: string,
  signature: string | null,
  secrets: string[],
): boolean {
  if (!signature || secrets.length === 0) return secrets.length === 0;
  return secrets.some((secret) => {
    const expected = `sha256=${crypto
      .createHmac("sha256", secret)
      .update(body)
      .digest("hex")}`;
    return signature === expected;
  });
}

export function verifyAzureDevOpsBasicAuth(
  authorization: string | null,
  secrets: string[],
): boolean {
  if (secrets.length === 0) return true;
  const got = parseBasicAuthPassword(authorization);
  if (!got) return false;
  return secrets.includes(got);
}

function parseBasicAuthPassword(authorization: string | null): string | null {
  if (!authorization?.startsWith("Basic ")) return null;
  try {
    const decoded = Buffer.from(authorization.slice(6), "base64").toString(
      "utf8",
    );
    const colon = decoded.indexOf(":");
    if (colon < 0) return decoded.trim() || null;
    return decoded.slice(colon + 1);
  } catch {
    return null;
  }
}

export async function requireGithubWebhookAuth(
  body: string,
  signature: string | null,
): Promise<
  | { ok: true; organizationId: string | null }
  | { ok: false; status: 401 }
> {
  const result = await verifyGithubSignatureWithOrg(body, signature);
  if (result === null) {
    return { ok: false, status: 401 };
  }
  return { ok: true, ...result };
}

/** Verify GitLab token and return the organization ID if valid. */
async function verifyGitlabTokenWithOrg(
  token: string | null,
): Promise<{ organizationId: string | null } | null> {
  if (!token) return null;
  const secrets = await listWebhookSecretsWithOrgs("gitlab");
  // Fail closed: no secret configured means no request can be authenticated.
  if (secrets.length === 0) return null;
  for (const { secret, organizationId } of secrets) {
    if (token === secret) return { organizationId };
  }
  return null;
}

export async function requireGitlabWebhookAuth(
  token: string | null,
): Promise<
  | { ok: true; organizationId: string | null }
  | { ok: false; status: 401 }
> {
  const result = await verifyGitlabTokenWithOrg(token);
  if (result === null) {
    return { ok: false, status: 401 };
  }
  return { ok: true, ...result };
}

export async function requireBitbucketWebhookAuth(
  body: string,
  signature: string | null,
): Promise<
  | { ok: true; organizationId: string | null }
  | { ok: false; status: 401 }
> {
  const result = await verifyBitbucketSignatureWithOrg(body, signature);
  if (result === null) {
    return { ok: false, status: 401 };
  }
  return { ok: true, ...result };
}

export async function requireAzureDevOpsWebhookAuth(
  authorization: string | null,
): Promise<
  | { ok: true; organizationId: string | null }
  | { ok: false; status: 401 }
> {
  const result = await verifyAzureDevOpsAuthWithOrg(authorization);
  if (result === null) {
    return { ok: false, status: 401 };
  }
  return { ok: true, ...result };
}
