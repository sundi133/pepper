import { prisma } from "@/lib/prisma";
import { decryptSecret, encryptSecret } from "@/lib/token-encryption";
import type {
  IntegrationConfigData,
  JiraConfig,
  SlackConfig,
  SiemConfig,
  DapperIntegrationConfig,
} from "./types";

export type {
  IntegrationConfigData,
  JiraConfig,
  SlackConfig,
  SiemConfig,
  DapperIntegrationConfig,
};

type Kind = IntegrationConfigData["kind"];

export async function listIntegrations(orgId: string) {
  const rows = await prisma.integrationConfig.findMany({
    where: { organizationId: orgId },
    orderBy: { createdAt: "desc" },
  });
  return rows.map((r) => ({
    id: r.id,
    kind: r.kind,
    name: r.name,
    enabled: r.enabled,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt,
  }));
}

export async function getIntegrationConfig<K extends Kind>(
  orgId: string,
  kind: K,
  id?: string,
): Promise<
  | (Extract<IntegrationConfigData, { kind: K }> & {
      id: string;
      enabled: boolean;
    })
  | null
> {
  const row = await prisma.integrationConfig.findFirst({
    where: {
      organizationId: orgId,
      kind,
      enabled: true,
      ...(id ? { id } : {}),
    },
    orderBy: { createdAt: "desc" },
  });
  if (!row) return null;
  try {
    const config = JSON.parse(decryptSecret(row.configEnc));
    return {
      id: row.id,
      enabled: row.enabled,
      kind,
      config,
    } as Extract<IntegrationConfigData, { kind: K }> & {
      id: string;
      enabled: boolean;
    };
  } catch {
    return null;
  }
}

export async function upsertIntegration(
  orgId: string,
  data: IntegrationConfigData & { name?: string; enabled?: boolean; id?: string },
) {
  const configEnc = encryptSecret(JSON.stringify(data.config));
  const name = data.name || defaultNameFor(data);
  if (data.id) {
    return prisma.integrationConfig.update({
      where: { id: data.id },
      data: {
        name,
        enabled: data.enabled ?? true,
        configEnc,
      },
    });
  }
  return prisma.integrationConfig.create({
    data: {
      organizationId: orgId,
      kind: data.kind,
      name,
      enabled: data.enabled ?? true,
      configEnc,
    },
  });
}

export async function deleteIntegration(orgId: string, id: string) {
  return prisma.integrationConfig.deleteMany({
    where: { id, organizationId: orgId },
  });
}

function defaultNameFor(data: IntegrationConfigData): string {
  switch (data.kind) {
    case "JIRA":
      return `Jira (${(data.config as JiraConfig).projectKey})`;
    case "SLACK":
      return `Slack (${(data.config as SlackConfig).channel || "default"})`;
    case "SIEM":
      return `SIEM (${(data.config as SiemConfig).format.toUpperCase()})`;
    case "DAST":
      return `Dapper (${new URL((data.config as DapperIntegrationConfig).endpoint).host})`;
  }
}
