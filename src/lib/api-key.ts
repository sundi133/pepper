import { createHash, randomBytes } from "crypto";
import { prisma } from "@/lib/prisma";

const API_KEY_PREFIX = "ppr";

export interface CreatedApiKey {
  id: string;
  /** Full plaintext key — shown ONCE to the user, never stored. */
  plaintext: string;
  prefix: string;
  name: string;
  expiresAt: Date | null;
}

function hashKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

export async function createApiKey(params: {
  organizationId: string;
  createdBy: string;
  name: string;
  expiresAt?: Date | null;
}): Promise<CreatedApiKey> {
  const random = randomBytes(24).toString("base64url");
  const plaintext = `${API_KEY_PREFIX}_${random}`;
  const prefix = plaintext.slice(0, 10);
  const keyHash = hashKey(plaintext);
  const row = await prisma.apiKey.create({
    data: {
      name: params.name,
      keyHash,
      prefix,
      organizationId: params.organizationId,
      createdBy: params.createdBy,
      expiresAt: params.expiresAt ?? null,
    },
  });
  return {
    id: row.id,
    plaintext,
    prefix: row.prefix,
    name: row.name,
    expiresAt: row.expiresAt,
  };
}

export async function verifyApiKey(headerValue: string | null | undefined) {
  if (!headerValue) return null;
  const raw = headerValue.startsWith("Bearer ")
    ? headerValue.slice("Bearer ".length).trim()
    : headerValue.trim();
  if (!raw.startsWith(`${API_KEY_PREFIX}_`)) return null;
  const keyHash = hashKey(raw);
  const row = await prisma.apiKey.findUnique({
    where: { keyHash },
    include: { organization: true },
  });
  if (!row) return null;
  if (row.expiresAt && row.expiresAt.getTime() < Date.now()) return null;
  // Best-effort update of lastUsedAt
  prisma.apiKey
    .update({
      where: { id: row.id },
      data: { lastUsedAt: new Date() },
    })
    .catch(() => undefined);
  return {
    apiKeyId: row.id,
    organizationId: row.organizationId,
    organization: row.organization,
  };
}

export async function revokeApiKey(orgId: string, id: string) {
  return prisma.apiKey.deleteMany({
    where: { id, organizationId: orgId },
  });
}

export async function listApiKeys(orgId: string) {
  return prisma.apiKey.findMany({
    where: { organizationId: orgId },
    select: {
      id: true,
      name: true,
      prefix: true,
      lastUsedAt: true,
      createdAt: true,
      expiresAt: true,
    },
    orderBy: { createdAt: "desc" },
  });
}
