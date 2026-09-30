/**
 * Just-in-time provisioning for Entra sign-ins: the same find-or-create and
 * role-raise as SAML, plus, with ENTRA_ROLE_SYNC=exact, lowering the role to
 * what Entra grants (never below the organization's last admin).
 */
import { prisma } from "@/lib/prisma";
import { logger } from "@/lib/logger";
import { writeAuditLog } from "@/lib/audit-log";
import { provisionSamlUser, resolveTargetOrgId } from "@/lib/saml/provision";
import type { Role } from "@/lib/saml/role-mapping";
import type { EntraConfig } from "./entra";

export async function provisionEntraUser(input: {
  email: string;
  name: string | null;
  role: Role;
  cfg: EntraConfig;
}): Promise<{ userId: string; organizationId: string }> {
  const organizationId = await resolveTargetOrgId(input.cfg.defaultOrgSlug);
  const { userId } = await provisionSamlUser({
    email: input.email,
    name: input.name,
    role: input.role,
    defaultOrgSlug: input.cfg.defaultOrgSlug,
  });
  if (input.cfg.roleSync === "exact") {
    await syncRoleExactly(userId, organizationId, input.role);
  }
  return { userId, organizationId };
}

async function syncRoleExactly(userId: string, organizationId: string, role: Role) {
  const member = await prisma.orgMember.findUnique({
    where: { userId_organizationId: { userId, organizationId } },
    select: { role: true },
  });
  if (!member || member.role === role) return;
  if (member.role === "ADMIN" && role !== "ADMIN") {
    const admins = await prisma.orgMember.count({ where: { organizationId, role: "ADMIN" } });
    if (admins <= 1) {
      logger.warn({ userId, organizationId, role }, "Entra role sync: kept ADMIN — this user is the organization's last admin");
      return;
    }
  }
  await prisma.orgMember.update({
    where: { userId_organizationId: { userId, organizationId } },
    data: { role },
  });
  await writeAuditLog({
    organizationId,
    userId,
    action: "user.role_changed",
    resource: "user",
    resourceId: userId,
    details: { from: member.role, to: role, method: "entra_role_sync" },
  });
}
