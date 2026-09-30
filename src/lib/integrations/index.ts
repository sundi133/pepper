import { prisma } from "@/lib/prisma";
import { decryptSecret, encryptSecret } from "@/lib/token-encryption";
import type {
  AzureBoardsConfig,
  IntegrationConfigData,
  JiraConfig,
  SlackConfig,
  SiemConfig,
  WebhookConfig,
} from "./types";

export type {
  AzureBoardsConfig,
  IntegrationConfigData,
  JiraConfig,
  SlackConfig,
  SiemConfig,
  WebhookConfig,
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

/** Where a ticket integration files issues; null for other kinds. */
function ticketTargetOf(data: IntegrationConfigData): string | null {
  if (data.kind === "AZURE_BOARDS") {
    const c = data.config as AzureBoardsConfig;
    if (!c?.organization?.trim()) return null;
    const host = c.serverUrl?.trim().replace(/\/+$/, "").toLowerCase() || "https://dev.azure.com";
    return `${host}/${c.organization.trim().toLowerCase()}/${(c.project?.trim() || "").toLowerCase()}`;
  }
  if (data.kind === "JIRA") {
    const c = data.config as JiraConfig;
    if (!c?.baseUrl?.trim() || !c.projectKey?.trim()) return null;
    return `${c.baseUrl.trim().replace(/\/+$/, "").toLowerCase()}/${c.projectKey.trim().toUpperCase()}`;
  }
  return null;
}

/**
 * The existing integration that files into the same board / Jira project, so
 * saving it again updates it instead of adding a duplicate that would file
 * (or fail) alongside it.
 */
export async function findSameTargetIntegration(orgId: string, data: IntegrationConfigData): Promise<string | null> {
  const target = ticketTargetOf(data);
  if (!target) return null;
  const rows = await prisma.integrationConfig.findMany({
    where: { organizationId: orgId, kind: data.kind },
    orderBy: { updatedAt: "desc" },
  });
  for (const r of rows) {
    try {
      const config = JSON.parse(decryptSecret(r.configEnc));
      if (ticketTargetOf({ kind: data.kind, config } as IntegrationConfigData) === target) return r.id;
    } catch {
      /* un-decryptable row: not a match */
    }
  }
  return null;
}

export async function upsertIntegration(
  orgId: string,
  data: IntegrationConfigData & { name?: string; enabled?: boolean; id?: string },
) {
  const configEnc = encryptSecret(JSON.stringify(data.config));
  const name = data.name || defaultNameFor(data);
  if (data.id) {
    // Scoped to the org: an id alone would let one org overwrite another's.
    const updated = await prisma.integrationConfig.updateMany({
      where: { id: data.id, organizationId: orgId },
      data: {
        name,
        enabled: data.enabled ?? true,
        configEnc,
      },
    });
    if (updated.count === 0) throw new IntegrationNotFoundError();
    return prisma.integrationConfig.findUniqueOrThrow({ where: { id: data.id } });
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

export class IntegrationNotFoundError extends Error {
  constructor() {
    super("Integration not found");
    this.name = "IntegrationNotFoundError";
  }
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
    case "AZURE_BOARDS": {
      const ab = data.config as AzureBoardsConfig;
      return `Azure Boards (${ab.project?.trim() || "repository's project"})`;
    }
    case "WEBHOOK": {
      const wh = data.config as WebhookConfig;
      try {
        return `Webhook (${new URL(wh.webhookUrl).host})`;
      } catch {
        return "Webhook";
      }
    }
    default:
      return "Integration";
  }
}
