import { prisma } from "@/lib/prisma";

/** Strip HTML tags to prevent stored XSS. */
function sanitizeText(value: string): string {
  return value.replace(/<[^>]*>/g, "").trim();
}

export async function createProjectWithBuildGate(params: {
  organizationId: string;
  name: string;
  description?: string | null;
  repoUrl?: string | null;
  defaultBranch?: string;
}) {
  const project = await prisma.project.create({
    data: {
      name: sanitizeText(params.name),
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
