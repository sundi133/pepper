import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";
import { uniqueOrganizationSlug } from "@/lib/org-slug";

export class RegisterUserError extends Error {
  constructor(
    public readonly code: "EMAIL_EXISTS" | "REGISTRATION_DISABLED",
    message: string,
  ) {
    super(message);
    this.name = "RegisterUserError";
  }
}

function defaultOrgSettings() {
  return {
    llmProvider: process.env.LLM_PROVIDER || "openrouter",
    llmBaseUrl: process.env.LLM_BASE_URL || "https://openrouter.ai/api/v1",
    llmModel: process.env.LLM_MODEL || "google/gemini-2.5-flash",
    ...(process.env.LLM_API_KEY ? { llmApiKey: process.env.LLM_API_KEY } : {}),
  };
}

export function isPublicRegistrationEnabled(): boolean {
  const raw = process.env.ALLOW_PUBLIC_REGISTRATION?.trim().toLowerCase();
  if (raw === "false" || raw === "0" || raw === "no") return false;
  return true;
}

export async function registerNewUser(params: {
  email: string;
  password: string;
  name?: string;
  organizationName: string;
}) {
  const email = params.email.trim().toLowerCase();
  const organizationName = params.organizationName.trim();

  const existing = await prisma.user.findUnique({
    where: { email },
    select: { id: true },
  });
  if (existing) {
    throw new RegisterUserError(
      "EMAIL_EXISTS",
      "An account with this email already exists. Sign in or ask an admin to invite you.",
    );
  }

  const passwordHash = await bcrypt.hash(params.password, 12);
  const slug = await uniqueOrganizationSlug(organizationName);
  const settings = defaultOrgSettings();

  return prisma.$transaction(async (tx) => {
    const organization = await tx.organization.create({
      data: {
        name: organizationName,
        slug,
      },
    });

    await tx.orgSettings.create({
      data: {
        organizationId: organization.id,
        ...settings,
      },
    });

    const user = await tx.user.create({
      data: {
        email,
        name: params.name?.trim() || null,
        passwordHash,
      },
      select: {
        id: true,
        email: true,
        name: true,
      },
    });

    await tx.orgMember.create({
      data: {
        userId: user.id,
        organizationId: organization.id,
        role: "ADMIN",
      },
    });

    return { user, organization };
  });
}
