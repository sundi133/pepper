import { prisma } from "@/lib/prisma";

export async function createProjectWithBuildGate(params: {
  organizationId: string;
  name: string;
  description?: string | null;
  repoUrl?: string | null;
  defaultBranch?: string;
}) {
  const project = await prisma.project.create({
    data: {
      name: params.name,
      description: params.description ?? undefined,
      repoUrl: params.repoUrl ?? null,
      defaultBranch: params.defaultBranch ?? "main",
      organizationId: params.organizationId,
    },
  });

  await prisma.buildGate.create({
    data: {
      projectId: project.id,
      maxCritical: 0,
      maxHigh: 5,
      maxMedium: 20,
      maxLow: -1,
    },
  });

  return project;
}
