import { prisma } from "@/lib/prisma";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";

/**
 * Find-or-create the throwaway project that holds a developer's pre-push scans.
 *
 * A scan creation always wipes the target project's prior scans
 * (removeAllScansForProject) because Scan.projectId is unique — one scan row per
 * project. A dev pre-push scan must therefore NOT land on a canonical project,
 * or it would delete that project's real scan and its findings/triage.
 *
 * Ephemeral projects are segregated by the `ephemeral` flag and matched only
 * against other ephemeral projects, so this can never select a canonical one
 * even when a developer's repo name collides with a real project. Repeated dev
 * scans of the same repo reuse the same ephemeral project (clobbering only the
 * previous dev scan, which is the intended behaviour — you only care about the
 * latest local result), rather than proliferating a new project each run.
 */
export async function resolveEphemeralProject(params: {
  organizationId: string;
  name: string;
  repoUrl?: string | null;
  defaultBranch?: string;
}): Promise<{ id: string; created: boolean }> {
  const existing = await prisma.project.findFirst({
    where: {
      organizationId: params.organizationId,
      name: params.name,
      ephemeral: true,
    },
    select: { id: true },
  });
  if (existing) return { id: existing.id, created: false };

  const project = await createProjectWithBuildGate({
    organizationId: params.organizationId,
    name: params.name,
    repoUrl: params.repoUrl ?? null,
    defaultBranch: params.defaultBranch ?? "main",
    ephemeral: true,
  });
  return { id: project.id, created: true };
}
