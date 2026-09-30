import { NextResponse } from "next/server";
import { requireRole } from "@/lib/auth-guard";

/**
 * Finding statuses that are risk decisions: they hide the finding from
 * counts and gates, and FALSE_POSITIVE also creates a suppression rule for
 * future scans. Only the Security role (or Admin) may set them; developers
 * can move findings between OPEN, IN_PROGRESS and RESOLVED.
 */
export const RISK_DECISION_STATUSES: ReadonlySet<string> = new Set(["FALSE_POSITIVE", "ACCEPTED_RISK"]);

export function isRiskDecisionStatus(status: string | null | undefined): boolean {
  return !!status && RISK_DECISION_STATUSES.has(status);
}

/** 403 with an actionable message unless the caller may make risk decisions. */
export async function requireRiskDecisionRole(orgId: string): Promise<NextResponse | null> {
  const roleAuth = await requireRole(orgId, "SECURITY");
  if (!("error" in roleAuth)) return null;
  if (roleAuth.error?.status === 401) return roleAuth.error;
  return NextResponse.json(
    {
      error:
        "Marking findings as false positive or accepted risk requires the Security or Admin role.",
      code: "RISK_DECISION_FORBIDDEN",
    },
    { status: 403 },
  );
}
