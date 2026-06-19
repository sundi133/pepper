import { createHash } from "crypto";
import { prisma } from "./prisma";
import type { RawFinding } from "@/scanners/types";

// ─── Types ──────────────────────────────────────────────────────────

type SuppressionRule = {
  id: string;
  ruleId: string | null;
  cweId: string | null;
  scanner: string | null;
  filePathPattern: string | null;
  titlePattern: string | null;
  snippetHash: string | null;
  reason: string;
};

type FindingLike = {
  ruleId?: string | null;
  cweId?: string | null;
  scanner?: string;
  filePath?: string | null;
  title?: string;
  snippet?: string | null;
};

// ─── Snippet Hashing ────────────────────────────────────────────────

function normalizeSnippet(snippet: string): string {
  return snippet
    .replace(/\s+/g, " ")
    .replace(/\d+/g, "N")
    .trim()
    .toLowerCase();
}

export function hashSnippet(snippet: string | null | undefined): string | null {
  if (!snippet?.trim()) return null;
  const normalized = normalizeSnippet(snippet);
  if (normalized.length < 10) return null;
  return createHash("sha256").update(normalized).digest("hex");
}

// ─── Rule Generation ────────────────────────────────────────────────

export async function generateSuppressionRule(params: {
  organizationId: string;
  projectId?: string | null;
  finding: {
    id: string;
    ruleId?: string | null;
    cweId?: string | null;
    scanner: string;
    filePath?: string | null;
    title: string;
    snippet?: string | null;
  };
  reason: string;
  userId?: string | null;
  source?: "user" | "auto" | "bulk";
}): Promise<void> {
  const { organizationId, projectId, finding, reason, userId, source } = params;

  // Don't create duplicate rules for the same finding
  const existing = await prisma.suppressionRule.findFirst({
    where: {
      organizationId,
      sourceFindingId: finding.id,
      enabled: true,
    },
  });
  if (existing) return;

  await prisma.suppressionRule.create({
    data: {
      organizationId,
      projectId: projectId || null,
      ruleId: finding.ruleId || null,
      cweId: finding.cweId || null,
      scanner: finding.scanner,
      filePathPattern: finding.filePath || null,
      titlePattern: finding.title.length > 10 ? finding.title : null,
      snippetHash: hashSnippet(finding.snippet),
      reason: reason || "Marked as false positive",
      source: source || "user",
      sourceFindingId: finding.id,
      createdBy: userId || null,
    },
  });
}

// ─── Rule Matching ──────────────────────────────────────────────────

function matchesRule(finding: FindingLike, rule: SuppressionRule): boolean {
  // Every non-null field on the rule must match. Null fields are wildcards.
  if (rule.ruleId && finding.ruleId !== rule.ruleId) return false;
  if (rule.cweId && finding.cweId !== rule.cweId) return false;
  if (rule.scanner && finding.scanner !== rule.scanner) return false;

  if (rule.filePathPattern && finding.filePath) {
    const pattern = rule.filePathPattern.toLowerCase();
    const fp = finding.filePath.toLowerCase();
    // Support both exact match and substring/basename match
    if (fp !== pattern && !fp.includes(pattern) && !fp.endsWith(pattern.split("/").pop() || "")) {
      return false;
    }
  } else if (rule.filePathPattern && !finding.filePath) {
    return false;
  }

  if (rule.titlePattern && finding.title) {
    if (!finding.title.toLowerCase().includes(rule.titlePattern.toLowerCase())) {
      return false;
    }
  } else if (rule.titlePattern && !finding.title) {
    return false;
  }

  if (rule.snippetHash) {
    const findingHash = hashSnippet(finding.snippet);
    if (findingHash !== rule.snippetHash) return false;
  }

  return true;
}

// ─── Filtering ──────────────────────────────────────────────────────

export async function filterSuppressedFindings(
  findings: RawFinding[],
  organizationId: string,
  projectId?: string,
): Promise<{
  kept: RawFinding[];
  suppressed: Array<{ finding: RawFinding; rule: SuppressionRule }>;
}> {
  // Fetch all active rules for this org (org-wide + project-specific)
  const rules = await prisma.suppressionRule.findMany({
    where: {
      organizationId,
      enabled: true,
      OR: [
        { projectId: null },
        ...(projectId ? [{ projectId }] : []),
      ],
      AND: [
        {
          OR: [
            { expiresAt: null },
            { expiresAt: { gt: new Date() } },
          ],
        },
      ],
    },
    select: {
      id: true,
      ruleId: true,
      cweId: true,
      scanner: true,
      filePathPattern: true,
      titlePattern: true,
      snippetHash: true,
      reason: true,
    },
  });

  if (rules.length === 0) {
    return { kept: findings, suppressed: [] };
  }

  const kept: RawFinding[] = [];
  const suppressed: Array<{ finding: RawFinding; rule: SuppressionRule }> = [];

  for (const f of findings) {
    const matchedRule = rules.find((r) => matchesRule(f, r));
    if (matchedRule) {
      suppressed.push({ finding: f, rule: matchedRule });
    } else {
      kept.push(f);
    }
  }

  return { kept, suppressed };
}

// ─── FP Examples for LLM Prompt ─────────────────────────────────────

export async function buildFpExamplesForPrompt(
  organizationId: string,
  limit = 20,
): Promise<string> {
  // Get recent FP findings with status notes from this org
  const fpFindings = await prisma.finding.findMany({
    where: {
      status: "FALSE_POSITIVE",
      statusNote: { not: null },
      scan: { project: { organizationId } },
    },
    select: {
      title: true,
      scanner: true,
      filePath: true,
      ruleId: true,
      cweId: true,
      statusNote: true,
    },
    orderBy: { statusUpdatedAt: "desc" },
    take: limit,
  });

  if (fpFindings.length === 0) return "";

  return fpFindings
    .map(
      (f, i) =>
        `Example FP ${i + 1}:\n` +
        `- Title: "${f.title}"\n` +
        `- Scanner: ${f.scanner}\n` +
        (f.filePath ? `- File: ${f.filePath}\n` : "") +
        (f.ruleId ? `- Rule: ${f.ruleId}\n` : "") +
        (f.cweId ? `- CWE: ${f.cweId}\n` : "") +
        `- Reason: "${f.statusNote}"`,
    )
    .join("\n\n");
}
