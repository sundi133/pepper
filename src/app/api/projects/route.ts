import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { requireAuth, getDefaultOrgId } from "@/lib/auth-guard";
import { z } from "zod";
import type { Prisma } from "@/generated/prisma/client";
import { letterGradeFromCounts, projectSourceLabel } from "@/lib/security-grade";
import { createProjectWithBuildGate } from "@/lib/create-project-with-build-gate";

/** Strip HTML tags and trim whitespace to prevent stored XSS. */
function sanitizeText(value: string): string {
  return value.replace(/<[^>]*>/g, "").trim();
}

const createProjectSchema = z.object({
  name: z
    .string()
    .min(1)
    .max(100)
    .transform(sanitizeText)
    .refine((v) => v.length > 0, "Name must not be empty after sanitization"),
  description: z.string().transform(sanitizeText).optional(),
  repoUrl: z.string().url().optional().or(z.literal("")),
  defaultBranch: z.string().default("main"),
});

function groupCount(
  rows: { scanId: string; _count: number | { _all: number } }[],
): Map<string, number> {
  const m = new Map<string, number>();
  for (const r of rows) {
    const n =
      typeof r._count === "number"
        ? r._count
        : (r._count as { _all: number })._all;
    m.set(r.scanId, n);
  }
  return m;
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  const { searchParams } = new URL(req.url);
  const q = searchParams.get("q")?.trim() ?? "";
  const source = searchParams.get("source") ?? "all";
  const sort = searchParams.get("sort") ?? "recent";

  const where: Prisma.ProjectWhereInput = { organizationId: orgId };
  if (q) {
    where.name = { contains: q, mode: "insensitive" };
  }
  if (source === "repo") {
    where.repoUrl = { not: null };
  } else if (source === "upload") {
    where.repoUrl = null;
  }

  const orderBy: Prisma.ProjectOrderByWithRelationInput =
    sort === "name" ? { name: "asc" } : { updatedAt: "desc" };

  const projects = await prisma.project.findMany({
    where,
    include: {
      _count: { select: { scans: true } },
      buildGate: true,
      scans: {
        orderBy: { createdAt: "desc" },
        take: 1,
        select: {
          id: true,
          status: true,
          gateResult: true,
          createdAt: true,
          completedAt: true,
          sourceType: true,
          criticalCount: true,
          highCount: true,
        },
      },
    },
    orderBy,
  });

  const projectIds = projects.map((p) => p.id);

  const latestCompleted =
    projectIds.length === 0
      ? []
      : await prisma.scan.findMany({
          where: {
            projectId: { in: projectIds },
            status: "COMPLETED",
          },
          orderBy: [{ projectId: "asc" }, { completedAt: "desc" }],
          distinct: ["projectId"],
          select: {
            id: true,
            projectId: true,
            completedAt: true,
            sourceType: true,
            criticalCount: true,
            highCount: true,
            mediumCount: true,
            lowCount: true,
            infoCount: true,
          },
        });

  const scanIds = latestCompleted.map((s) => s.id);

  const [secretsByScan, depsByScan] =
    scanIds.length === 0
      ? [[], []]
      : await Promise.all([
          prisma.finding.groupBy({
            by: ["scanId"],
            where: {
              scanId: { in: scanIds },
              scanner: { in: ["SECRETS_PATTERN", "SECRETS_LLM"] },
            },
            _count: true,
          }),
          prisma.finding.groupBy({
            by: ["scanId"],
            where: {
              scanId: { in: scanIds },
              scanner: { in: ["SCA", "MALICIOUS_PKG"] },
            },
            _count: true,
          }),
        ]);

  const secretsMap = groupCount(
    secretsByScan as { scanId: string; _count: number | { _all: number } }[],
  );
  const depsMap = groupCount(
    depsByScan as { scanId: string; _count: number | { _all: number } }[],
  );
  const completedByProject = new Map(
    latestCompleted.map((s) => [s.projectId, s]),
  );

  type Card = {
    sourceLabel: "Repository" | "Uploaded";
    lastScanAt: string | null;
    grade: "A" | "B" | "C" | "D" | "F" | null;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    totalFindings: number;
    secretsCount: number;
    depsCount: number;
  };

  const enriched = projects.map((p) => {
    const lc = completedByProject.get(p.id);
    const lastTouch = p.scans[0];
    const c = lc?.criticalCount ?? 0;
    const h = lc?.highCount ?? 0;
    const m = lc?.mediumCount ?? 0;
    const l = lc?.lowCount ?? 0;
    const inf = lc?.infoCount ?? 0;
    const total = c + h + m + l + inf;

    const grade = lc ? letterGradeFromCounts(c, h, m, l) : null;
    const secretsCount = lc ? (secretsMap.get(lc.id) ?? 0) : 0;
    const depsCount = lc ? (depsMap.get(lc.id) ?? 0) : 0;

    const lastScanAt =
      lc?.completedAt?.toISOString() ??
      lastTouch?.completedAt?.toISOString() ??
      lastTouch?.createdAt?.toISOString() ??
      null;

    const sourceSt = lc?.sourceType ?? lastTouch?.sourceType;
    const sourceLabel = projectSourceLabel(p.repoUrl, sourceSt ?? null);

    const card: Card = {
      sourceLabel,
      lastScanAt,
      grade,
      criticalCount: c,
      highCount: h,
      mediumCount: m,
      lowCount: l,
      infoCount: inf,
      totalFindings: total,
      secretsCount,
      depsCount,
    };

    return { ...p, card };
  });

  let list = enriched;
  if (sort === "vulns") {
    list = [...enriched].sort(
      (a, b) => b.card.totalFindings - a.card.totalFindings,
    );
  } else if (sort === "grade") {
    const rank: Record<string, number> = {
      A: 5,
      B: 4,
      C: 3,
      D: 2,
      F: 1,
    };
    list = [...enriched].sort((a, b) => {
      const ga = a.card.grade ? rank[a.card.grade] : 0;
      const gb = b.card.grade ? rank[b.card.grade] : 0;
      if (gb !== ga) return gb - ga;
      return b.card.totalFindings - a.card.totalFindings;
    });
  }

  return NextResponse.json({ projects: list });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth();
  if ("error" in auth) return auth.error;

  const orgId = getDefaultOrgId(auth.session);
  if (!orgId) {
    return NextResponse.json({ error: "No organization" }, { status: 403 });
  }

  try {
    const body = await req.json();
    const data = createProjectSchema.parse(body);

    const project = await createProjectWithBuildGate({
      organizationId: orgId,
      name: data.name,
      description: data.description,
      repoUrl: data.repoUrl || null,
      defaultBranch: data.defaultBranch,
    });

    return NextResponse.json(project, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: "Invalid input", details: error.issues },
        { status: 400 },
      );
    }
    return NextResponse.json(
      { error: "Failed to create project" },
      { status: 500 },
    );
  }
}
