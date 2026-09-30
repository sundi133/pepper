/**
 * Just-in-time provisioning for SAML SSO users (single global IdP).
 *
 * On a validated assertion we find-or-create the User by email and ensure an
 * OrgMember in the target organization with the IdP-group-derived role.
 *
 * Safety: SSO can RAISE a user's role but never lowers it here — if an existing
 * member already has a higher role than the mapping grants, we keep it. This
 * prevents a misconfigured group map from locking an on-prem admin out of their
 * own install. Downgrade/deprovisioning is deliberately deferred to the SCIM
 * phase.
 */

import { prisma } from "@/lib/prisma";
import { higherRole, type Role } from "./role-mapping";
import { writeAuditLog } from "@/lib/audit-log";

export class SamlProvisionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SamlProvisionError";
  }
}

async function resolveTargetOrgId(defaultOrgSlug: string): Promise<string> {
  if (defaultOrgSlug) {
    const org = await prisma.organization.findUnique({
      where: { slug: defaultOrgSlug },
      select: { id: true },
    });
    if (!org) {
      throw new SamlProvisionError(
        `SAML_DEFAULT_ORG_SLUG "${defaultOrgSlug}" does not match any organization`,
      );
    }
    return org.id;
  }
  // Single-tenant on-prem default: the oldest (first-created) organization.
  const oldest = await prisma.organization.findFirst({
    orderBy: { createdAt: "asc" },
    select: { id: true },
  });
  if (!oldest) {
    throw new SamlProvisionError(
      "No organization exists to provision the SSO user into",
    );
  }
  return oldest.id;
}

export async function provisionSamlUser(input: {
  email: string;
  name?: string | null;
  role: Role;
  defaultOrgSlug: string;
}): Promise<{ userId: string }> {
  const email = input.email.trim().toLowerCase();
  if (!email) {
    throw new SamlProvisionError("SAML assertion did not include an email");
  }
  const organizationId = await resolveTargetOrgId(input.defaultOrgSlug);
  const name = input.name?.trim() || null;

  const changes: { created: boolean; joined: boolean; roleFrom?: Role; roleTo?: Role } = {
    created: false,
    joined: false,
  };
  const result = await prisma.$transaction(async (tx) => {
    let user = await tx.user.findUnique({
      where: { email },
      select: { id: true, name: true },
    });
    if (!user) {
      user = await tx.user.create({
        data: { email, name, emailVerified: new Date() },
        select: { id: true, name: true },
      });
      changes.created = true;
    } else if (!user.name && name) {
      await tx.user.update({ where: { id: user.id }, data: { name } });
    }

    const membership = await tx.orgMember.findUnique({
      where: {
        userId_organizationId: { userId: user.id, organizationId },
      },
      select: { role: true },
    });

    if (!membership) {
      await tx.orgMember.create({
        data: { userId: user.id, organizationId, role: input.role },
      });
      changes.joined = true;
    } else {
      const effective = higherRole(membership.role as Role, input.role);
      if (effective !== membership.role) {
        await tx.orgMember.update({
          where: {
            userId_organizationId: { userId: user.id, organizationId },
          },
          data: { role: effective },
        });
        changes.roleFrom = membership.role as Role;
        changes.roleTo = effective;
      }
    }

    return { userId: user.id };
  });

  // SSO-driven account and role changes, attributed to the user signing in.
  const base = { organizationId, userId: result.userId, resource: "user" as const, resourceId: result.userId };
  if (changes.created || changes.joined) {
    await writeAuditLog({
      ...base,
      action: "user.created",
      details: { email, role: input.role, method: "saml", newAccount: changes.created },
    });
  }
  if (changes.roleFrom && changes.roleTo) {
    await writeAuditLog({
      ...base,
      action: "user.role_changed",
      details: { email, from: changes.roleFrom, to: changes.roleTo, method: "saml_group_mapping" },
    });
  }
  return result;
}
