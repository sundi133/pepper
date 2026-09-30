import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/prisma", () => ({
  prisma: {
    integrationConfig: {
      updateMany: vi.fn(),
      findUniqueOrThrow: vi.fn(),
      create: vi.fn(),
    },
  },
}));
vi.mock("@/lib/token-encryption", () => ({ encryptSecret: (s: string) => `enc:${s}`, decryptSecret: (s: string) => s }));

import { prisma } from "@/lib/prisma";
import { IntegrationNotFoundError, upsertIntegration } from "./index";

describe("upsertIntegration", () => {
  beforeEach(() => vi.clearAllMocks());

  it("only updates an integration that belongs to the caller's org", async () => {
    vi.mocked(prisma.integrationConfig.updateMany).mockResolvedValue({ count: 0 });
    await expect(
      upsertIntegration("org-a", { id: "int-of-org-b", kind: "SLACK", config: { webhookUrl: "https://x" } }),
    ).rejects.toBeInstanceOf(IntegrationNotFoundError);
    expect(prisma.integrationConfig.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { id: "int-of-org-b", organizationId: "org-a" } }),
    );
  });

  it("updates and returns the row when it's the caller's", async () => {
    vi.mocked(prisma.integrationConfig.updateMany).mockResolvedValue({ count: 1 });
    vi.mocked(prisma.integrationConfig.findUniqueOrThrow).mockResolvedValue({ id: "i1", kind: "SLACK" } as never);
    await expect(
      upsertIntegration("org-a", { id: "i1", kind: "SLACK", config: { webhookUrl: "https://x" } }),
    ).resolves.toMatchObject({ id: "i1" });
  });

  it("names Azure Boards integrations after the project", async () => {
    vi.mocked(prisma.integrationConfig.create).mockImplementation((async (a: { data: unknown }) => a.data) as never);
    const row = await upsertIntegration("org-a", { kind: "AZURE_BOARDS", config: { organization: "acme", project: "Payments" } });
    expect(row).toMatchObject({ name: "Azure Boards (Payments)", kind: "AZURE_BOARDS", configEnc: expect.stringMatching(/^enc:/) });
  });
});
