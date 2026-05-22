import { prisma } from "@/lib/prisma";

/** URL-safe organization slug from a display name. */
export function slugifyOrganizationName(name: string): string {
  const slug = name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
  return slug.length > 0 ? slug : "org";
}

/** Pick a slug that is not already taken. */
export async function uniqueOrganizationSlug(baseName: string): Promise<string> {
  const base = slugifyOrganizationName(baseName);
  let candidate = base;
  let suffix = 0;

  while (
    await prisma.organization.findUnique({
      where: { slug: candidate },
      select: { id: true },
    })
  ) {
    suffix += 1;
    candidate = `${base}-${suffix}`;
  }

  return candidate;
}
